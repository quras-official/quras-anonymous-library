#include "common\global.h"
#include "QurasModules\streams.h"

#ifdef __cplusplus    // If used by C++ code, 
extern "C" {          // we need to export the C interface
#endif

#define EXPORT extern __declspec( dllexport )

	EXPORT QRIncrementalMerkleTree* CmMerkleTree_Create()
	{
		QRIncrementalMerkleTree * ret = new QRIncrementalMerkleTree();
		return ret;
	}

	EXPORT QRIncrementalWitness* CmWitness_Create()
	{
		QRIncrementalWitness * ret = new QRIncrementalWitness();
		return ret;
	}

	EXPORT const char* GetCMTreeInBinary(QRIncrementalMerkleTree * gtree, int* out_length)
	{
		CDataStream ss(SER_NETWORK, 1);
		ss << *gtree;

		std::string hex = ss.str();

		out_length[0] = ss.size();
		return hex.c_str();
	}

	EXPORT bool SetCMTreeFromOthers(QRIncrementalMerkleTree* dst, QRIncrementalMerkleTree* src)
	{
		*dst = *src;
		return true;
	}

	EXPORT const char* GetCMWitnessInBinary(QRIncrementalWitness * gWitness, int* out_length)
	{
		CDataStream ss(SER_NETWORK, 1);
		ss << *gWitness;

		std::string hex = ss.str();

		out_length[0] = ss.size();
		return hex.c_str();
	}

	EXPORT bool SetCMTreeFromBinary(QRIncrementalMerkleTree * gtree, char* bnTree, int size)
	{
		CDataStream ss1(bnTree, bnTree + size, SER_NETWORK, 1);
		ss1 >> *gtree;

		return true;
	}

	EXPORT bool SetCMWitnessFromBinary(QRIncrementalWitness * gWitness, char* bnTree, int size)
	{
		CDataStream ss1(bnTree, bnTree + size, SER_NETWORK, 1);
		ss1 >> *gWitness;

		return true;
	}

	EXPORT bool AppendCommitment(QRIncrementalMerkleTree * gtree, char* cm)
	{
		uint256 u_cm = ConvertFromBytes(cm);
		gtree->append(u_cm);
		return true;
	}

	EXPORT bool AppendCommitmentInWitness(QRIncrementalWitness * gWitness, char* cm)
	{
		uint256 u_cm = ConvertFromBytes(cm);
		gWitness->append(u_cm);
		return true;
	}

	EXPORT char* GetCMRoot(QRIncrementalMerkleTree * gtree)
	{
		libquras::SHA256Compress rt = gtree->root();

		char* byRet = new char[rt.size()];
		memcpy(byRet, rt.begin(), rt.size());

		return byRet;
	}

	EXPORT char* GetCMRootFromWitness(QRIncrementalWitness * gWtiness)
	{
		libquras::SHA256Compress rt = gWtiness->root();

		char* byRet = new char[rt.size()];
		memcpy(byRet, rt.begin(), rt.size());

		return byRet;
	}

	EXPORT void GetWitnessFromMerkleTree(QRIncrementalWitness* gWitness, QRIncrementalMerkleTree* MerkleTree)
	{
		*gWitness = MerkleTree->witness();
	}

	EXPORT const char* GetWitnessInBytes(QRIncrementalMerkleTree * gtree, int* out_length)
	{
		QRIncrementalWitness w = gtree->witness();

		CDataStream ss(SER_NETWORK, 1);
		ss << *gtree;

		std::string hex = ss.str();

		out_length[0] = ss.size();
		return hex.c_str();
	}

	EXPORT const char* AddCmInWitness(char* byWitness, int size, char* cm, int* out_length)
	{
		CDataStream ss1(byWitness, byWitness + size, SER_NETWORK, 1);
		QRIncrementalWitness w;
		ss1 >> w;

		uint256 u_cm = ConvertFromBytes(cm);
		w.append(u_cm);

		CDataStream ss(SER_NETWORK, 1);
		ss << w;

		std::string hex = ss.str();

		out_length[0] = ss.size();
		return hex.c_str();
	}
#ifdef __cplusplus
}
#endif