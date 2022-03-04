/**********************************************************************
 * Copyright (c) 2013, 2014, 2015 Thomas Daede, Cory Fields           *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#define USE_BASIC_CONFIG 1

#include "basic-config.h"
#include "include/secp256k1.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_gen_impl.h"

static void default_error_callback_fn(const char* str, void* data) {
    (void)data;
    DbgPrint("[libsecp256k1] internal consistency check failed: %s\n", str);
    //abort();
}

static const secp256k1_callback default_error_callback = {
    default_error_callback_fn,
    NULL
};

int main(int argc, char **argv) {
    secp256k1_ecmult_gen_context ctx;
    int inner;
    int outer;
    //FILE* fp;

    (void)argc;
    (void)argv;

    //fp = fopen("src/ecmult_static_context.h","w");
    //if (fp == NULL) {
    //    DbgPrint("Could not open src/ecmult_static_context.h for writing!\n");
    //    return -1;
    //}
    
    DbgPrint("#ifndef _SECP256K1_ECMULT_STATIC_CONTEXT_\n");
    DbgPrint("#define _SECP256K1_ECMULT_STATIC_CONTEXT_\n");
    DbgPrint("#include \"group.h\"\n");
    DbgPrint("#define SC SECP256K1_GE_STORAGE_CONST\n");
    DbgPrint("static const secp256k1_ge_storage secp256k1_ecmult_static_context[64][16] = {\n");

    secp256k1_ecmult_gen_context_init(&ctx);
    secp256k1_ecmult_gen_context_build(&ctx, &default_error_callback);
    for(outer = 0; outer != 64; outer++) {
        DbgPrint("{\n");
        for(inner = 0; inner != 16; inner++) {
            DbgPrint("    SC(%uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu, %uu)", SECP256K1_GE_STORAGE_CONST_GET((*ctx.prec)[outer][inner]));
            if (inner != 15) {
                DbgPrint(",\n");
            } else {
                DbgPrint("\n");
            }
        }
        if (outer != 63) {
            DbgPrint("},\n");
        } else {
            DbgPrint("}\n");
        }
    }
    DbgPrint("};\n");
    secp256k1_ecmult_gen_context_clear(&ctx);
    
    DbgPrint("#undef SC\n");
    DbgPrint("#endif\n");
    //fclose(fp);
    
    return 0;
}
