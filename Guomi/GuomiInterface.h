//
//  GuomiInterface.h
//  GuomiDemo
//
//  Created by 王军建 on 2017/10/26.
//  Copyright © 2017年 狗吃草. All rights reserved.
//

#ifndef GuomiInterface_h
#define GuomiInterface_h

#include <stdio.h>

void gm_buffer2hexstr(const unsigned char *buffer, long len, char *hexstr);
void gm_hexstr2buffer(const char *hexstr, unsigned char *buffer, long *buffer_len);

void gm_generate_random(long random_num_size, unsigned char *random_num);

void gm_sm2_generate_keys(const char *random_num, char *public_key, char *private_key);
void gm_sm2_encrypt(const char *public_key, const unsigned char *text, long text_length, char unsigned *encrypted_text);
void gm_sm2_decrypt(const char *private_key, const unsigned char *encrypted_text, long encrypted_text_length, char unsigned *text);

void gm_sm3(const unsigned char *buffer, long buffer_length, char *hash_code);

long gm_sm4_calc_encrypted_data_memory_size(long data_len);
void gm_sm4_encrypt(const unsigned char *key, const unsigned char *input, long len, unsigned char *output);
void gm_sm4_decrypt(const unsigned char *key, const unsigned char *input, long len, unsigned char *output);

#endif /* GuomiInterface_h */
