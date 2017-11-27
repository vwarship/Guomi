#ifndef PART4_H
#define PART4_H

#include "sm2.h"

typedef struct
{
    BYTE *message;
    int message_byte_length;
    //BYTE *encrypt;
    BYTE *decrypt;
    int klen_bit;
    
    BYTE k[MAX_POINT_BYTE_LENGTH];  //ÀÊª˙ ˝
    BYTE private_key[MAX_POINT_BYTE_LENGTH];
    struct
    {
        BYTE x[MAX_POINT_BYTE_LENGTH];
        BYTE y[MAX_POINT_BYTE_LENGTH];
    }public_key;
    
    BYTE C[1024];    // C_1 || C_2 || C_3
    BYTE C_1[1024];
    BYTE C_2[1024];  //º”√‹∫Ûµƒœ˚œ¢
    BYTE C_3[1024];
    
} message_st;

int sm2_encrypt(ec_param *ecp, message_st *message_data);
int sm2_decrypt(ec_param *ecp, message_st *message_data);


void test_part4(char **sm2_param, int type, int point_bit_length);

void sm2JiaMi(char **sm2_param, int type, int point_bit_length , char *mingwen,char *miwen);
void sm2Jiemi(char **sm2_param, int type, int point_bit_length , char *miwen ,char output[] );

//使用传入的公钥加密
void sm2JiaMiWithPublicKey(char **sm2_param, int type, int point_bit_length , char mingwen[],char *miwen,unsigned char px[],unsigned char py[]);

#endif//
