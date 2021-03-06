#include "stdafx.h"
#include "stdio.h"
#include "QurasModules\QurasCrypto.h"
#include "QurasModules\JoinSplit.h"

#include "QurasModules\crypto\common.h"
#include "QurasModules\random.h"
#include "QurasModules\proof.h"
#include "QurasModules\streams.h"
#include "QurasModules\utilstrencodings.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/function.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>

#include "test\joinsplit_test.h"
#include "common\global.h"
#include "AsyncJoinSplitInfo.h"

extern "C" { FILE _iob[3] = { __acrt_iob_func(0), __acrt_iob_func(1), __acrt_iob_func(2) }; }

//FILE _iob[] = { *stdin, *stdout, *stderr };
extern "C" FILE * __cdecl __iob_func(void) { return _iob; }


#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>

#include <iostream>
#include <sstream>

#include <libsnark/gadgetlib2/examples/simple_example.hpp>
#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/gadgetlib2/pp.hpp>
#include <libsnark/gadgetlib2/protoboard.hpp>

using namespace libsnark;
using namespace libquras;


template<typename ppT>
void test_r1cs_ppzksnark(size_t num_constraints,
	size_t input_size)
{
	libff::print_header("(enter) Test R1CS ppzkSNARK");

	const bool test_serialization = true;
	r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
	const bool bit = run_r1cs_ppzksnark<ppT>(example, test_serialization);
	assert(bit);

	libff::print_header("(leave) Test R1CS ppzkSNARK");
}

bool QR_LibffInit()
{
	if (init_and_check_sodium() == -1)
		return false;

	libsnark::default_r1cs_ppzksnark_pp::init_public_params();

	return true;
}

int QR_LoadParams(int nMode, char* vkPath, char* pkPath)
{
	int ret = -1;

	//libsnark::default_r1cs_ppzksnark_pp::init_public_params();
	//libff::inhibit_profiling_info = true;
	//libff::inhibit_profiling_counters = true;

	if (init_and_check_sodium() == -1)
		return -2;

	boost::filesystem::path pk_path = pkPath;
	boost::filesystem::path vk_path = vkPath;

	if (!boost::filesystem::exists(pk_path))
	{
		pk_path = ".//crypto//pk.key";
	}

	if (!boost::filesystem::exists(vk_path))
	{
		vk_path = ".//crypto//vk.key";
	}

	switch (nMode)
	{
	case 1: // Load vk
	{
		if (!(boost::filesystem::exists(vk_path))) {
			return -3;
		}
		try {
			pqurasParams = QRJoinSplit::Prepared(vk_path.string(), pk_path.string());
			ret = 1;
		}
		catch (std::exception e)
		{
			ret = -4;
		}
		break;
	}
	case 2: // load pk
	{
		if (!(boost::filesystem::exists(pk_path))) {
			return -3;
		}

		if (pqurasParams->LoadPk(pk_path.string()))
			ret = 1;
		else
			ret = -5;
		break;
	}
	default: // Init only libff
		ret = -6;
		break;
	}

	return ret;
}

#ifdef __cplusplus    // If used by C++ code, 
extern "C" {          // we need to export the C interface
#endif

#define EXPORT extern __declspec( dllexport )

typedef struct Temp
{
	int * iVal;
	char * chVal;
}MyTemp;

EXPORT void ctestFillStructure(MyTemp *iTempVal)
{
	/*
	iTempVal->iVal = (int*) malloc(sizeof(int));
	iTempVal->chVal = (char*) malloc(5);

	*((*iTempVal).iVal) = 500;
	strcpy(iTempVal->chVal,"Moh");
	*/

	printf("Hello");
	return;
}

EXPORT void Do_TEST(int* a)
{
	printf("Hello");

	gadgetlib2::initPublicParamsFromDefaultPp();
	const r1cs_example<libff::Fr<default_r1cs_ppzksnark_pp> > example = gen_r1cs_example_from_gadgetlib2_protoboard(100);
	int n = example.auxiliary_input.size();
	const bool test_serialization = false;

	const bool bit = run_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(example, test_serialization);

	printf("%d", bit);
}

EXPORT int DLL_INIT(int nMode, char* vkPath, char* pkPath)
{
	return QR_LoadParams(nMode, vkPath, pkPath);
}

EXPORT bool MakeProof(char* pubKeyHash, char* anchor, char** input, char** output, uint64_t vpub_old, uint64_t vpub_new)
{
	//pubKeyHash,
	//	anchor,
	//{ JSInput(), JSInput() },
	//{ JSOutput(), JSOutput() },
	//	0,
	//	0

	std::vector<unsigned char> buffer;
	for (int i = 0; i < 32; i++)
	{
		buffer.push_back(pubKeyHash[i]);
	}
	uint256 pubKeyHash_(buffer);

	buffer.clear();
	for (int i = 0; i < 32; i++)
	{
		buffer.push_back(anchor[i]);
	}
	
	uint256 anchor_(buffer);

	test_joinsplit();
	return true;
}

#ifdef __cplusplus
}
#endif

int main(int argc, char* argv[])
{
	if (argc == 2)
	{
		uint256 SeedValue = uint256S(argv[1]);
		test_generate_key(SeedValue);
		
	}
	else if (argc == 3)
	{
		std::string sPath = argv[1];
		int nSize = atoi(argv[2]);

		return verify_constraint_file(sPath, nSize);
	}
	else if (argc == 4)
	{
		uint256 SeedValue = uint256S(argv[1]);
		int nStart = atoi(argv[2]);
		int nSize = atoi(argv[3]);

		generate_constraint_file(SeedValue, nStart, nSize);
	}
	else
	{
		test_generate_key_by_constraint();
		//generate_constraint_file(0, 1000);
		//test_genereate_key();

		//DLL_INIT(1, "", "");
		//DLL_INIT(2, "", "");
		//MakeProof();

		//test_joinsplit();
		//test_note_encrypt();
		// test_merkle_tree();

		//test_joinsplit_locals();
	}
	
	

	return 0;
}
