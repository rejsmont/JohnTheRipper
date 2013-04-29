/*
 * Copyright 2013, epixoip.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that redistribution of source
 * retains the above copyright.
 *
 * Code signficinatly changed, by Jim Fougeron, 2013, to move the crypt
 * logic into sse-intrinsics.c.  This code released with the following terms:
 * No copyright is claimed, and the software is hereby placed in the public domain.
 * In case this attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is Copyright (c) 2011 JimF
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

#include "arch.h"
#ifdef MMX_COEF_SHA256

#include <string.h>
#include "stdint.h"
#include "common.h"
#include "formats.h"
#include "sse-intrinsics.h"

#include "memdbg.h"

#define FORMAT_LABEL              "raw-sha256-ng-i"
#define FORMAT_NAME               "Raw SHA-256"
#define ALGORITHM_NAME            SHA256_ALGORITHM_NAME
#define FORMAT_TAG                "$SHA256$"
#define TAG_LENGTH                8

#define NUMKEYS                   MMX_COEF_SHA256

#define BENCHMARK_COMMENT         ""
#define BENCHMARK_LENGTH          -1

#define MAXLEN                    55
#define CIPHERTEXT_LENGTH         64
#define DIGEST_SIZE               32
#define BINARY_SIZE               32
#define BINARY_ALIGN              4
#define SALT_SIZE                 0
#define SALT_ALIGN                1
#define MIN_KEYS_PER_CRYPT        MMX_COEF_SHA256
#define MAX_KEYS_PER_CRYPT        MMX_COEF_SHA256

static struct fmt_tests tests[] = {
    {"71c3f65d17745f05235570f1799d75e69795d469d9fcb83e326f82f1afa80dea", "epixoip"},
    {"25b64f637b373d33a8aa2b7579784e99a20e6b7dfea99a71af124394b8958f27", "doesthiswork"},
    {"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password"},
    {"27c6794c8aa2f70f5f6dc93d3bfb25ca6de9b0752c8318614cbd4ad203bea24c", "ALLCAPS"},
    {"04cdd6c523673bf448efe055711a9b184817d7843b0a76c2046f5398b5854152", "TestTESTt3st"},
    {FORMAT_TAG "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f", "12345678"},
    {FORMAT_TAG "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ""},
#ifdef DEBUG
    {"9e7d3e56996c5a06a6a378567e62f5aa7138ebb0f55c0bdaf73666bf77f73380", "mot\xf6rhead"},
    {"0f46e4b0802fee6fed599682a16287d0397699cfd742025482c086a70979e56a", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 31
    {"c62e4615bd39e222572f3a1bf7c2132ea1e65b17ec805047bd6b2842c593493f", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 32
    {"d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}, // 55
#endif
    {NULL}
};

static uint32_t (*saved_key)[64];
static uint32_t *crypt_key[8];

static void init(struct fmt_main *self)
{
    int i;
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
    for (i = 0; i < 8; i++)
        crypt_key[i] = mem_calloc_tiny(sizeof(uint32_t) * self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
}


static int valid (char *ciphertext, struct fmt_main *self)
{
    char *p, *q;

    p = ciphertext;

    if (! strncmp (p, FORMAT_TAG, TAG_LENGTH))
        p += TAG_LENGTH;

    q = p;
    while (atoi16[ARCH_INDEX(*q)] != 0x7F) q++;

    return !*q && q - p == CIPHERTEXT_LENGTH;
}


#if FMT_MAIN_VERSION > 9
static char *split (char *ciphertext, int index, struct fmt_main *self)
#else
static char *split (char *ciphertext, int index)
#endif
{
    static char out[TAG_LENGTH + CIPHERTEXT_LENGTH + 1];

    if (!strncmp (ciphertext, FORMAT_TAG, TAG_LENGTH))
        return ciphertext;

    memcpy (out,  FORMAT_TAG, TAG_LENGTH);
    memcpy (out + TAG_LENGTH, ciphertext, CIPHERTEXT_LENGTH + 1);
    strlwr (out + TAG_LENGTH);

    return out;
}


static void *get_binary (char *ciphertext)
{
    static unsigned char *out;
    int i;

    if (!out)
        out = mem_alloc_tiny (DIGEST_SIZE, MEM_ALIGN_WORD);

    ciphertext += TAG_LENGTH;

    for(i=0; i < BINARY_SIZE; i++)
        out[i] = atoi16[ARCH_INDEX(ciphertext[i*2])] * 16 +
                 atoi16[ARCH_INDEX(ciphertext[i*2 + 1])];

    alter_endianity (out, DIGEST_SIZE);

    return (void *) out;
}


static int binary_hash_0 (void *binary) { return *(uint32_t *) binary & 0xf; }
static int binary_hash_1 (void *binary) { return *(uint32_t *) binary & 0xff; }
static int binary_hash_2 (void *binary) { return *(uint32_t *) binary & 0xfff; }
static int binary_hash_3 (void *binary) { return *(uint32_t *) binary & 0xffff; }
static int binary_hash_4 (void *binary) { return *(uint32_t *) binary & 0xfffff; }
static int binary_hash_5 (void *binary) { return *(uint32_t *) binary & 0xffffff; }
static int binary_hash_6 (void *binary) { return *(uint32_t *) binary & 0x7ffffff; }

static int get_hash_0 (int index) { return crypt_key[0][index] & 0xf; }
static int get_hash_1 (int index) { return crypt_key[0][index] & 0xff; }
static int get_hash_2 (int index) { return crypt_key[0][index] & 0xfff; }
static int get_hash_3 (int index) { return crypt_key[0][index] & 0xffff; }
static int get_hash_4 (int index) { return crypt_key[0][index] & 0xfffff; }
static int get_hash_5 (int index) { return crypt_key[0][index] & 0xffffff; }
static int get_hash_6 (int index) { return crypt_key[0][index] & 0x7ffffff; }


static void set_key (char *key, int index)
{
    uint32_t *buf32 = (uint32_t *) (saved_key[index]);
    uint8_t  *buf8  = (uint8_t *) buf32;
    int len = 0;

    while (*key)
	    buf8[len++] = *key++;
    buf32[15] = (len << 3);
    buf8[len++] = 0x80;
    while (buf8[len] && len <= MAXLEN)
        buf8[len++] = 0;

	//for (len=0; len<16; ++len)
	//	printf("%08x ", buf32[len]);
	//printf("\n");
}


static char *get_key (int index)
{
    uint32_t *buf = (uint32_t *) &saved_key[index];
    static char out[MAXLEN + 1];

    int len = buf[15] >> 3;

    memset (out, 0, MAXLEN + 1);
    memcpy (out, buf, len);

    return (char *) out;
}


#if FMT_MAIN_VERSION > 10
static int crypt_all (int *pcount, struct db_salt *salt)
#else
static void crypt_all (int count)
#endif
{
#if FMT_MAIN_VERSION > 10
    int count = *pcount;
#endif

	SSESHA256body_Flat(saved_key, crypt_key, 1);

#if FMT_MAIN_VERSION > 10
    return count;
#endif
}


static int cmp_all (void *binary, int count)
{
    int i;

    for (i = 0; i < count; i++)
        if (((uint32_t *) binary)[0] == crypt_key[0][i])
             return 1;
    return 0;
}


static int cmp_one (void *binary, int index)
{
    int i;

    for (i=1; i < 8; i++)
        if (((uint32_t *) binary)[i] != crypt_key[i][index])
            return 0;

    return 1;
}


static int cmp_exact (char *source, int index)
{
    return 1;
}


struct fmt_main fmt_rawSHA256_ng_i = {
    {
        FORMAT_LABEL,
        FORMAT_NAME,
        ALGORITHM_NAME,
        BENCHMARK_COMMENT,
        BENCHMARK_LENGTH,
        MAXLEN,
        BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
        BINARY_ALIGN,
#endif
        SALT_SIZE,
#if FMT_MAIN_VERSION > 9
        SALT_ALIGN,
#endif
        MIN_KEYS_PER_CRYPT,
        MAX_KEYS_PER_CRYPT,
        FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP,
        tests
    }, {
        init,
#if FMT_MAIN_VERSION > 10
        fmt_default_done,
        fmt_default_reset,
#endif
        fmt_default_prepare,
        valid,
        split,
        get_binary,
        fmt_default_salt,
#if FMT_MAIN_VERSION > 9
        fmt_default_source,
#endif
        {
            binary_hash_0,
            binary_hash_1,
            binary_hash_2,
            binary_hash_3,
            binary_hash_4,
            binary_hash_5,
            binary_hash_6
        },
        fmt_default_salt_hash,
        fmt_default_set_salt,
        set_key,
        get_key,
        fmt_default_clear_keys,
        crypt_all,
        {
            get_hash_0,
            get_hash_1,
            get_hash_2,
            get_hash_3,
            get_hash_4,
            get_hash_5,
            get_hash_6
        },
        cmp_all,
        cmp_one,
        cmp_exact
    }
};

#endif
