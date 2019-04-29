 //***************************************************************
 // @file:    des.c
 // @author:  dingfang
 // @date    2019-04-28 21:41:53
 //***************************************************************
 
#include "des.h"

#include <stdio.h>
#include <string.h>
#include <openssl/des.h>

int DesEncode(char *const input, int inSize, char *output, int *outSize, unsigned char *const key, unsigned char *iv)
{
	return DEScrypto(input, inSize, output, outSize, key, iv, DES_ENCRYPT);
}

int DesDecode(char *const input, int inSize, char *output, int *outSize, unsigned char *const key, unsigned char *iv)
{
	return DEScrypto(input, inSize, output, outSize, key, iv, DES_DECRYPT);
}

static int DEScrypto(char *const input, int len, char *output, int *outlen, unsigned char *const key, unsigned char *iv, int enc) 
{
	*outlen = 0;
	unsigned short int padding;
	unsigned long number_of_blocks;
	unsigned long block_count		= 0;
	unsigned char *data_block		= (unsigned char *) malloc(8 * sizeof(char));
	unsigned char *processed_block	= (unsigned char *) malloc(8 * sizeof(char));

	number_of_blocks = len / 8 + ((len % 8) ? 0 : -1);

	DES_cblock ivec;
	memcpy(ivec, iv, sizeof(ivec));
	DES_key_schedule key_sch;
	DES_set_key_unchecked((const_DES_cblock *) key, &key_sch);

	for (block_count = 0; block_count < number_of_blocks; ++block_count) 
	{
		*outlen += 8;
		memcpy(data_block, input + block_count * 8, 8);
		DES_ncbc_encrypt(data_block , processed_block, 8, &key_sch, &ivec, enc);
		memcpy(output + block_count * 8, processed_block, 8);
		memset(data_block, 0, 8);
	}
	if (block_count == number_of_blocks) 
	{
		padding = 8 - len % 8;
		memcpy(data_block, input + block_count * 8, 8 - padding % 8);
		if (enc == DES_ENCRYPT)
		{
			*outlen += 8;
			if (padding < 8) 
			{
				memset((data_block + 8 - padding), (unsigned char)padding, padding);
			}
			DES_ncbc_encrypt(data_block , processed_block, 8, &key_sch, &ivec, enc);
			memcpy(output + block_count * 8, processed_block, 8);

			if (padding == 8) 
			{
				*outlen += 8;
				memset(data_block, (unsigned char)padding, 8);
				DES_ncbc_encrypt(data_block , processed_block, 8, &key_sch, &ivec, enc);
				memcpy(output + block_count * 8 + 8, processed_block, 8);
			}
		}
		else
		{
			DES_ncbc_encrypt(data_block , processed_block, 8, &key_sch, &ivec, enc);
			padding = processed_block[7];
			if (padding < 8) 
			{
				*outlen += 8 - padding;
				memcpy(output + block_count * 8, processed_block, 8);
			}
		}
	} 

	free(data_block);
	free(processed_block);

	return 0;
}


unsigned char iv[] = {8, 15, 4, 51, 33, 24, 8, 81};
unsigned char key[] = "k|m3!nv)";
int outlen = 0;

void test1(char *input)
{
	printf("* * * * * * * * * * * * * * * * * * * * * * * * *\n");
	char output[2048] = { 0 };
	printf("input: %s\n", input);
	DesEncode(input, strlen(input), output, &outlen, key, iv);
	printf("encode: %s\n", output);

	memset(input, 0x00, sizeof(input));
	DesDecode(output, outlen, input, &outlen, key, iv);
	printf("decode: %s\n", input);
	printf("* * * * * * * * * * * * * * * * * * * * * * * * *\n\n");

	return ;
}

int main(void)
{
	char input[2048] = { 0 };
	strcpy(input, "01234567");
	test1(input);

	memset(input, 0x00, sizeof(input));
	strcpy(input, "fjaskd0123adkljf;fjasdjflaj;fjsdkfjaklsdjfkljalk567");
	test1(input);

	memset(input, 0x00, sizeof(input));
	strcpy(input, "456");
	test1(input);

	return 0;
}
 
