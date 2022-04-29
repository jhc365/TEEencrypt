/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define _CRT_SECURE_NO_WARNINGS

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEENCRYPT_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	//contains param[0]: text string, param[1]: key string
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	/*
	op.params[0].value.a = 42;
	*/

	/*
	 * TA_HELLO_WORLD_CMD_INC_VALUE is the actual function in the TA to be
	 * called.
	 */

	//mode selection

	//make txtfile for test

	FILE *ft = fopen("test.txt", "w");

	fputs("hello,world for test",ft);

	fclose(ft);
	

	if(strcmp(argv[1] ,"-e") == 0){//rsa encrypt
		
		//open plaintext txtfile and get plaintext
		//char object for rsa
		char clear[RSA_MAX_PLAIN_LEN_1024];
		char ciph[RSA_CIPHER_LEN_1024];

		FILE *fe = fopen(argv[2],"r");

		fgets(clear, sizeof(clear), fe);

		op.params[0].tmpref.buffer = clear;
		op.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
		op.params[1].value.a = 0;//initialized key value 0


		memcpy(op.params[0].tmpref.buffer, clear, RSA_MAX_PLAIN_LEN_1024);

		fclose(fe);

		//invoke encryption

		res = TEEC_InvokeCommand(&sess, TA_TEEENCRYPT_CMD_INC_VALUE, &op,
				 &err_origin);

		//print & write on file that encrypted string
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Ciphertext : %s\n", ciphertext);

		FILE *fi = fopen("cipher.txt","w");
		fputs(ciphertext, fi);
		fclose(fi);
		//write encrypted key to file

		char k_buf[64];
	
		sprintf(k_buf, "%d", op.params[1].value.a);

		FILE *fp = fopen("key.txt", "w");
	
		printf("encrypted key : %s\n",k_buf);

		fputs(k_buf,fp);

		fclose(fp);
		
	
	} else if(strcmp(argv[1] ,"-d") == 0){

		//open ciphertext txtfile and get plaintext

		FILE *fe = fopen(argv[2],"r");

		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = len;

		fgets(ciphertext, sizeof(ciphertext),fe);


		memcpy(op.params[0].tmpref.buffer, ciphertext, len);

		fclose(fe);

		//open key txt file and get encrypted key

		int key;
		char k_buf[64];//keytext buffer

		FILE *fp = fopen(argv[3], "r"); //get 3rd argv param as filename

		fgets(k_buf, sizeof(k_buf),fp);

		key = atoi(k_buf);

		op.params[1].value.a = key; //set key in params

		fclose(fp);

		//invoke decryption

		printf("Decryption. opening %s \n", argv[2]);
		printf("encrypted key : %d \n", key);

		res = TEEC_InvokeCommand(&sess, TA_TEEENCRYPT_CMD_DEC_VALUE, &op,
				 &err_origin);

		//print & enfile decryption
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext : %s\n", plaintext);

		FILE *fi = fopen("intext.txt","w");
		fputs(plaintext, fi);
		fclose(fi);
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
