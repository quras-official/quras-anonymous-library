#include "global.h"
#include "..\AsyncJoinSplitInfo.h"
#include "..\QurasModules\transaction\transaction.h"

#include "..\QurasModules\QurasCrypto.h"
#include "..\QurasModules\JoinSplit.h"

#include "..\QurasModules\crypto\common.h"

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>

QRJoinSplit* pqurasParams = NULL;

JSDescription* ConvertBytetoJSD(char* byte)
{
	JSDescription* jsd = new JSDescription();

	char* ptr_data;
	ptr_data = byte;

	memcpy(&jsd->vpub_old, ptr_data, sizeof(CAmount));
	ptr_data += sizeof(CAmount);
	memcpy(&jsd->vpub_new, ptr_data, sizeof(CAmount));
	ptr_data += sizeof(CAmount);

	std::vector<unsigned char> buffer;

	buffer.clear();
	for (int i = 0; i < 32; i++)
	{
		buffer.push_back(*ptr_data);
		ptr_data++;
	}
	jsd->Asset_Id = uint256(buffer);

	buffer.clear();
	for (int i = 0; i < 32; i++)
	{
		buffer.push_back(*ptr_data);
		ptr_data++;
	}
	jsd->anchor = uint256(buffer);

	for (int i = 0; i < QR_NUM_JS_INPUTS; i++)
	{
		buffer.clear();
		for (int i = 0; i < 32; i++)
		{
			buffer.push_back(*ptr_data);
			ptr_data++;
		}
		jsd->nullifiers[i] = uint256(buffer);
	}

	for (int i = 0; i < QR_NUM_JS_OUTPUTS; i++)
	{
		buffer.clear();
		for (int i = 0; i < 32; i++)
		{
			buffer.push_back(*ptr_data);
			ptr_data++;
		}
		jsd->commitments[i] = uint256(buffer);
	}

	buffer.clear();
	for (int i = 0; i < 32; i++)
	{
		buffer.push_back(*ptr_data);
		ptr_data++;
	}
	jsd->ephemeralKey = uint256(buffer);

	buffer.clear();
	for (int i = 0; i < 32; i++)
	{
		buffer.push_back(*ptr_data);
		ptr_data++;
	}
	jsd->randomSeed = uint256(buffer);

	for (int i = 0; i < QR_NUM_JS_INPUTS; i++)
	{
		buffer.clear();
		for (int i = 0; i < 32; i++)
		{
			buffer.push_back(*ptr_data);
			ptr_data++;
		}
		jsd->macs[i] = uint256(buffer);
	}

	for (int i = 0; i < QR_NUM_JS_OUTPUTS; i++)
	{
		short ciphersize;
		memcpy(&ciphersize, ptr_data, sizeof(short));
		ptr_data += sizeof(short);
		memcpy(jsd->ciphertexts[i].begin(), ptr_data, ciphersize);
		ptr_data += ciphersize;
	}

	std::string coord;
	char buff[100] = { 0 };
	unsigned char coord_size;

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_A.coord[0].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_A.coord[1].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_A.coord[2].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_A_prime.coord[0].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_A_prime.coord[1].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_A_prime.coord[2].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_B.coord[0].a_.set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_B.coord[0].b_.set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_B.coord[1].a_.set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_B.coord[1].b_.set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_B.coord[2].a_.set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_B.coord[2].b_.set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_B_prime.coord[0].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_B_prime.coord[1].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_B_prime.coord[2].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_C.coord[0].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_C.coord[1].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_C.coord[2].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_C_prime.coord[0].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_C_prime.coord[1].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_C_prime.coord[2].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_H.coord[0].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_H.coord[1].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_H.coord[2].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_K.coord[0].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_K.coord[1].set(coord);

	memcpy(&coord_size, ptr_data, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memset(buff, 0, sizeof(buff));
	memcpy(buff, ptr_data, coord_size);
	ptr_data += coord_size;
	coord = buff;
	jsd->proof.g_K.coord[2].set(coord);

	ptr_data = NULL;
	return jsd;
}

char* ConvertJSDtoByte(JSDescription jsd, int& num_bits)
{
	int jsd_length = 0;

	jsd_length += sizeof(CAmount);						//vpub_old
	jsd_length += sizeof(CAmount);						//vpub_new
	jsd_length += 32;									//Asset_id
	jsd_length += 32;									//anchor
	jsd_length += QR_NUM_JS_INPUTS * 32;				//nullifiers
	jsd_length += QR_NUM_JS_OUTPUTS * 32;				//commitments
	jsd_length += 32;									//ephermeralKey
	jsd_length += 32;									//randomSeed
	jsd_length += QR_NUM_JS_INPUTS * 32;				//macs
	jsd_length += jsd.proof.Size();						// proof size
	jsd_length += QR_NUM_JS_OUTPUTS * QRNoteEncryption::Ciphertext::size();

	num_bits = jsd_length + 1;

	char* data = new char[jsd_length + 1];
	char* ptr_data;

	memset(data, 0, jsd_length + 1);

	ptr_data = data;
	memcpy(ptr_data, &jsd.vpub_old, sizeof(CAmount));
	ptr_data += sizeof(CAmount);
	memcpy(ptr_data, &jsd.vpub_new, sizeof(CAmount));
	ptr_data += sizeof(CAmount);

	memcpy(ptr_data, jsd.Asset_Id.begin(), 32);
	ptr_data += 32;

	memcpy(ptr_data, jsd.anchor.begin(), 32);
	ptr_data += 32;
	for (int i = 0; i < QR_NUM_JS_INPUTS; i++)
	{
		memcpy(ptr_data, jsd.nullifiers[i].begin(), 32);
		ptr_data += 32;
	}

	for (int i = 0; i < QR_NUM_JS_OUTPUTS; i++)
	{
		memcpy(ptr_data, jsd.commitments[i].begin(), 32);
		ptr_data += 32;
	}

	memcpy(ptr_data, jsd.ephemeralKey.begin(), 32);
	ptr_data += 32;

	memcpy(ptr_data, jsd.randomSeed.begin(), 32);
	ptr_data += 32;

	for (int i = 0; i < QR_NUM_JS_INPUTS; i++)
	{
		memcpy(ptr_data, jsd.macs[i].begin(), 32);
		ptr_data += 32;
	}

	for (int i = 0; i < QR_NUM_JS_OUTPUTS; i++)
	{
		short ciphersize = jsd.ciphertexts[i].size();
		memcpy(ptr_data, &ciphersize, sizeof(short));
		ptr_data += sizeof(short);
		memcpy(ptr_data, jsd.ciphertexts[i].begin(), jsd.ciphertexts[i].size());
		ptr_data += jsd.ciphertexts[i].size();
	}

	//g_A
	unsigned char coord_size;
	coord_size = jsd.proof.g_A.coord[0].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_A.coord[0].toString(16).c_str(), jsd.proof.g_A.coord[0].toString(16).size());
	ptr_data += jsd.proof.g_A.coord[0].toString(16).size();

	coord_size = jsd.proof.g_A.coord[1].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_A.coord[1].toString(16).c_str(), jsd.proof.g_A.coord[1].toString(16).size());
	ptr_data += jsd.proof.g_A.coord[1].toString(16).size();

	coord_size = jsd.proof.g_A.coord[2].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_A.coord[2].toString(16).c_str(), jsd.proof.g_A.coord[2].toString(16).size());
	ptr_data += jsd.proof.g_A.coord[2].toString(16).size();

	//g_A_prime
	coord_size = jsd.proof.g_A_prime.coord[0].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_A_prime.coord[0].toString(16).c_str(), jsd.proof.g_A_prime.coord[0].toString(16).size());
	ptr_data += jsd.proof.g_A_prime.coord[0].toString(16).size();

	coord_size = jsd.proof.g_A_prime.coord[1].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_A_prime.coord[1].toString(16).c_str(), jsd.proof.g_A_prime.coord[1].toString(16).size());
	ptr_data += jsd.proof.g_A_prime.coord[1].toString(16).size();

	coord_size = jsd.proof.g_A_prime.coord[2].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_A_prime.coord[2].toString(16).c_str(), jsd.proof.g_A_prime.coord[2].toString(16).size());
	ptr_data += jsd.proof.g_A_prime.coord[2].toString(16).size();

	//g_B
	coord_size = jsd.proof.g_B.coord[0].a_.toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_B.coord[0].a_.toString(16).c_str(), jsd.proof.g_B.coord[0].a_.toString(16).size());
	ptr_data += jsd.proof.g_B.coord[0].a_.toString(16).size();

	coord_size = jsd.proof.g_B.coord[0].b_.toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_B.coord[0].b_.toString(16).c_str(), jsd.proof.g_B.coord[0].b_.toString(16).size());
	ptr_data += jsd.proof.g_B.coord[0].b_.toString(16).size();

	coord_size = jsd.proof.g_B.coord[1].a_.toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_B.coord[1].a_.toString(16).c_str(), jsd.proof.g_B.coord[1].a_.toString(16).size());
	ptr_data += jsd.proof.g_B.coord[1].a_.toString(16).size();

	coord_size = jsd.proof.g_B.coord[1].b_.toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_B.coord[1].b_.toString(16).c_str(), jsd.proof.g_B.coord[1].b_.toString(16).size());
	ptr_data += jsd.proof.g_B.coord[1].b_.toString(16).size();

	coord_size = jsd.proof.g_B.coord[2].a_.toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_B.coord[2].a_.toString(16).c_str(), jsd.proof.g_B.coord[2].a_.toString(16).size());
	ptr_data += jsd.proof.g_B.coord[2].a_.toString(16).size();

	coord_size = jsd.proof.g_B.coord[2].b_.toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_B.coord[2].b_.toString(16).c_str(), jsd.proof.g_B.coord[2].b_.toString(16).size());
	ptr_data += jsd.proof.g_B.coord[2].b_.toString(16).size();

	//g_B_prime
	coord_size = jsd.proof.g_B_prime.coord[0].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_B_prime.coord[0].toString(16).c_str(), jsd.proof.g_B_prime.coord[0].toString(16).size());
	ptr_data += jsd.proof.g_B_prime.coord[0].toString(16).size();

	coord_size = jsd.proof.g_B_prime.coord[1].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_B_prime.coord[1].toString(16).c_str(), jsd.proof.g_B_prime.coord[1].toString(16).size());
	ptr_data += jsd.proof.g_B_prime.coord[1].toString(16).size();

	coord_size = jsd.proof.g_B_prime.coord[2].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_B_prime.coord[2].toString(16).c_str(), jsd.proof.g_B_prime.coord[2].toString(16).size());
	ptr_data += jsd.proof.g_B_prime.coord[2].toString(16).size();

	//g_C
	coord_size = jsd.proof.g_C.coord[0].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_C.coord[0].toString(16).c_str(), jsd.proof.g_C.coord[0].toString(16).size());
	ptr_data += jsd.proof.g_C.coord[0].toString(16).size();

	coord_size = jsd.proof.g_C.coord[1].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_C.coord[1].toString(16).c_str(), jsd.proof.g_C.coord[1].toString(16).size());
	ptr_data += jsd.proof.g_C.coord[1].toString(16).size();

	coord_size = jsd.proof.g_C.coord[2].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_C.coord[2].toString(16).c_str(), jsd.proof.g_C.coord[2].toString(16).size());
	ptr_data += jsd.proof.g_C.coord[2].toString(16).size();

	//g_C_prime
	coord_size = jsd.proof.g_C_prime.coord[0].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_C_prime.coord[0].toString(16).c_str(), jsd.proof.g_C_prime.coord[0].toString(16).size());
	ptr_data += jsd.proof.g_C_prime.coord[0].toString(16).size();

	coord_size = jsd.proof.g_C_prime.coord[1].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_C_prime.coord[1].toString(16).c_str(), jsd.proof.g_C_prime.coord[1].toString(16).size());
	ptr_data += jsd.proof.g_C_prime.coord[1].toString(16).size();

	coord_size = jsd.proof.g_C_prime.coord[2].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_C_prime.coord[2].toString(16).c_str(), jsd.proof.g_C_prime.coord[2].toString(16).size());
	ptr_data += jsd.proof.g_C_prime.coord[2].toString(16).size();

	//g_H
	coord_size = jsd.proof.g_H.coord[0].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_H.coord[0].toString(16).c_str(), jsd.proof.g_H.coord[0].toString(16).size());
	ptr_data += jsd.proof.g_H.coord[0].toString(16).size();

	coord_size = jsd.proof.g_H.coord[1].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_H.coord[1].toString(16).c_str(), jsd.proof.g_H.coord[1].toString(16).size());
	ptr_data += jsd.proof.g_H.coord[1].toString(16).size();

	coord_size = jsd.proof.g_H.coord[2].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_H.coord[2].toString(16).c_str(), jsd.proof.g_H.coord[2].toString(16).size());
	ptr_data += jsd.proof.g_H.coord[2].toString(16).size();

	//g_K
	coord_size = jsd.proof.g_K.coord[0].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_K.coord[0].toString(16).c_str(), jsd.proof.g_K.coord[0].toString(16).size());
	ptr_data += jsd.proof.g_K.coord[0].toString(16).size();

	coord_size = jsd.proof.g_K.coord[1].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_K.coord[1].toString(16).c_str(), jsd.proof.g_K.coord[1].toString(16).size());
	ptr_data += jsd.proof.g_K.coord[1].toString(16).size();

	coord_size = jsd.proof.g_K.coord[2].toString(16).size();
	memcpy(ptr_data, &coord_size, sizeof(unsigned char));
	ptr_data += sizeof(unsigned char);
	memcpy(ptr_data, jsd.proof.g_K.coord[2].toString(16).c_str(), jsd.proof.g_K.coord[2].toString(16).size());
	ptr_data += jsd.proof.g_K.coord[2].toString(16).size();

	return data;
}

char* g_FindMyNotes(char* jsdescription, char* private_key, char* join_split_pub_key)
{
	char * ret;
	QR_LibffInit();

	std::vector<unsigned char> buffer;
	for (int i = 31; i >= 0; i--)
	{
		buffer.push_back(join_split_pub_key[i]);
	}

	uint256 joinsplit_pubkey(buffer);

	buffer.clear();
	for (int i = 31; i >= 0; i--)
	{
		buffer.push_back(private_key[i]);
	}

	uint256 _pk(buffer);
	uint252 pk(_pk);

	libquras::SpendingKey sk(pk);

	libquras::PaymentAddress pa = sk.address();

	JSDescription* jsd = ConvertBytetoJSD(jsdescription);

	if (pqurasParams == NULL)
	{
		QR_LoadParams(1, "", "");
	}

	if (pqurasParams != NULL)
	{
		uint256 hSig = jsd->h_sig(*pqurasParams, joinsplit_pubkey);
		std::vector<JSTransactionOutput> vOutput;
		for (int i = 0; i < jsd->ciphertexts.size(); i++)
		{
			try {
				QRNoteDecryption dec(sk.viewing_key().sk_enc);
				auto note_pt = libquras::NotePlaintext::decrypt(
					dec,
					jsd->ciphertexts[i],
					jsd->ephemeralKey,
					hSig,
					(unsigned char)i);

				auto note = note_pt.note(sk.address());
				// SpendingKeys are only available if:
				// - We have them (this isn't a viewing key)
				// - The wallet is unlocked
				
				auto nullifier = note.nullifier(sk);

				JSTransactionOutput item;
				item.index = (char)i;
				memcpy(item.a_pk, pa.a_pk.begin(), pa.a_pk.size());
				memcpy(item.pk_enc, pa.pk_enc.begin(), pa.pk_enc.size());
				memcpy(item.rho, note_pt.rho.begin(), note_pt.rho.size());
				memcpy(item.r, note_pt.r.begin(), note_pt.r.size());
				memcpy(item.Value, &note_pt.value, sizeof (note_pt.value));

				vOutput.push_back(item);
			}
			catch (const note_decryption_failed &err) {
				// Couldn't decrypt with this decryptor
			}
			catch (const std::exception &exc) {
				// Unexpected failure
			}
		}
		int nCount = vOutput.size();
		ret = new char[1 + nCount * sizeof(JSTransactionOutput)];
		ret[0] = (char)nCount;

		for (int i = 0; i < nCount; i++)
		{
			memcpy(ret + 1 + i * sizeof(JSTransactionOutput), &vOutput.at(i), sizeof(JSTransactionOutput));
		}

		return ret;
	}

	ret = new char[1];
	ret[0] = 0;
	return ret;
}

uint256 ConvertFromBytes(char* arg)
{
	std::vector<unsigned char> buffer;
	for (int i = 31; i >= 0; i--)
	{
		buffer.push_back(arg[i]);
	}
	uint256 ret(buffer);

	return ret;
}

uint256 ConvertFromBytesInv(char* arg)
{
	std::vector<unsigned char> buffer;
	for (int i = 0; i < 32; i++)
	{
		buffer.push_back(arg[i]);
	}
	uint256 ret(buffer);

	return ret;
}
