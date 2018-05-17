#ifndef _EEA3ZUC_H_
#define _EEA3ZUC_H_

#include <ppfu/ppfu.h>


/*------------------------------------------------------------------------
* ZUC.h
* Code taken from the ZUC specification
* available on the GSMA website
*------------------------------------------------------------------------*/

/* type definition from */
typedef unsigned char u8;
typedef unsigned int u32;

/*
* ZUC keystream generator
* k: secret key (input, 16 bytes)
* iv: initialization vector (input, 16 bytes)
* Keystream: produced keystream (output, variable length)
* KeystreamLen: length in bits requested for the keystream (input)
*/
void Initialization(zuc_ctx_t* ctx, u8* k, u8* iv);
//void GenerateKeystream(zuc_ctx_t* ctx, u32* pKeystream, u32 KeystreamLen);

/*
* CK: ciphering key
* COUNT: frame counter
* BEARER: radio bearer
* DIRECTION
* LENGTH: length of the frame in bits
* M: original message (input)
* C: processed message (output)
*/
void EEA3(zuc_ctx_t* ctx,u8* CK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u32* M, u32* C);

/*
* IK: integrity key
* COUNT: frame counter
* BEARER: radio bearer
* DIRECTION
* LENGTH: length of the frame in bits
* M: original message (input)
* C: processed message (output)
*/
void EIA3(zuc_ctx_t* ctx, u8* IK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u32* M, u8* MAC);


/* void zuc_encrypt(uint32_t user, uint8_t* dst, uint8_t* src, uint16_t len, SecurityContext* sctxt); */

void zuc_encrypt(zuc_ctx_t* ctx, u8* key, u32 count, u32 bearer, u8* data, u8* output, u32 length);
void zuc_decrypt(zuc_ctx_t* ctx, u8* key, u32 count, u32 bearer, u8* data, u8* output, u32 length);

void zuc_protect (zuc_ctx_t* ctx, u8* key, u32 count, u32 bearer, u8* data, u32 length, u8* MAC);
void zuc_validate(zuc_ctx_t* ctx, u8* key, u32 count, u32 bearer, u8* data, u32 length, u8* MAC);
#endif
