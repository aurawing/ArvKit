#include <secp256k1.h>

#include "stdbool.h"
#include "stdint.h"
#include "ntdef.h"
#include "random.h"
#include "sha256.h"
#include "base58.h"
#include "ripemd160.h"

bool ArvVerifySig(char *msg, char *sig58, char *pubkey58)
{
	//������Կ��У��
	size_t pubkey58len = strlen(pubkey58);
	if (pubkey58len > 51)
	{
		return false; //��Կ���ȹ���
	}
	size_t pubkeylen = 40; //��Կ����
	unsigned char pubkeybytes[40];
	bool ret = b58tobin(pubkeybytes, &pubkeylen, pubkey58, pubkey58len);
	if (!ret)
	{
		return false; //base58����ʧ��
	}
	if (pubkeylen != 37)
	{
		return false; //��Կ���Ȳ���
	}
	unsigned char *rawpubkey = (unsigned char*)pubkeybytes + 40 - pubkeylen; //��Կ
	uint8_t pubkeyhash[20];
	ripemd160(rawpubkey, 33, pubkeyhash);
	if (memcmp(&rawpubkey[33], pubkeyhash, 4) != 0)
	{
		return false; //checksum����
	}

	//����ǩ����У��
	char *rawSig58 = NULL;
	if (strlen(sig58) > 7 && memcmp(sig58, "SIG_K1_", 7) == 0)
	{
		rawSig58 = &sig58[7];
	}
	if (rawSig58 == NULL || strlen(rawSig58) > 95)
	{
		return false; //ǩ�����ȹ���
	}
	size_t sig58len = strlen(rawSig58);
	size_t siglen = 80;
	char sigbytes[80];
	ret = b58tobin(sigbytes, &siglen, rawSig58, sig58len);
	if (!ret)
	{
		return false; //base58����ʧ��
	}
	if (siglen != 69)
	{
		return false; //ǩ�����Ȳ���
	}
	unsigned char *rawsigbytes = (unsigned char*)sigbytes + 80 - siglen; //��Կ
	char sig65 = rawsigbytes[65];
	char sig66 = rawsigbytes[66];
	rawsigbytes[65] = 'K';
	rawsigbytes[66] = '1';
	uint8_t sighash[20];
	ripemd160(rawsigbytes, 67, sighash);
	rawsigbytes[65] = sig65;
	rawsigbytes[66] = sig66;
	if (memcmp(&rawsigbytes[65], sighash, 4) != 0)
	{
		return false; //checksum����
	}

	//��ǩ
	unsigned char msg_hash[SHA256_BLOCK_SIZE];
	unsigned char *serialized_signature = &rawsigbytes[1];
	SHA256_CTX sha256ctx;
	size_t msg_len = strlen(msg);
	sha256_init(&sha256ctx);
	sha256_update(&sha256ctx, msg, msg_len);
	sha256_final(&sha256ctx, msg_hash);

	unsigned char *compressed_pubkey = rawpubkey;
	secp256k1_pubkey pubkey;
	secp256k1_ecdsa_signature sig;
	size_t len;
	int is_signature_valid;
	int return_val;
	secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_signature)) {
		return false; //����ǩ��ʧ��
	}
	if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed_pubkey, 33)) {
		return false; //��ǩʧ��
	}
	is_signature_valid = secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pubkey);
	secp256k1_context_destroy(ctx);
	return is_signature_valid;
}