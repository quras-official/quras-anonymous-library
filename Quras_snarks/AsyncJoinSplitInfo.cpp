#include "AsyncJoinSplitInfo.h"
#include "common\global.h"

#ifdef __cplusplus    // If used by C++ code, 
extern "C" {          // we need to export the C interface
#endif

#define EXPORT extern __declspec( dllexport )

	EXPORT AsyncJoinSplitInfo* AsyncJoinSplitInfo_Create()
	{
		AsyncJoinSplitInfo * ret = new AsyncJoinSplitInfo;
		return ret;
	}

	EXPORT void AsyncJoinSplitInfo_Delete(AsyncJoinSplitInfo* info)
	{
		delete info;
	}

	EXPORT void AsyncJoinSplitInfo_Add_JSOutput(AsyncJoinSplitInfo* info, JSOutput* output)
	{
		info->vjsout.push_back(*output);
	}

	EXPORT void AsyncJoinSplitInfo_Add_JSInput(AsyncJoinSplitInfo* info, JSInput* input)
	{
		info->vjsin.push_back(*input);
	}

	EXPORT void AsyncJoinSplitInfo_Add_Notes(AsyncJoinSplitInfo* info, Note* note)
	{
		info->notes.push_back(*note);
	}

	EXPORT void AsyncJoinSplitInfo_Add_Amount(AsyncJoinSplitInfo* info, CAmount vpub_old, CAmount vpub_new, char* byAsset_ID)
	{
		info->vpub_new = vpub_new;
		info->vpub_old = vpub_old;
		info->AssetID = ConvertFromBytesInv(byAsset_ID);
	}

	EXPORT Note* Note_Create()
	{
		return new Note();
	}

	EXPORT void Note_Delete(Note* pNote)
	{
		delete pNote;
	}

	//uint256 a_pk;
	//uint64_t value;
	//uint256 rho;
	//uint256 r;
	//uint256 assetID;
	EXPORT void Note_Init(Note* pNote, char* a_pk_, char* rho_, char* r_, CAmount value, char* assetID_)
	{
		uint256 a_pk = ConvertFromBytesInv(a_pk_);
		uint256 rho = ConvertFromBytesInv(rho_);
		uint256 r = ConvertFromBytesInv(r_);
		uint256 assetID = ConvertFromBytesInv(assetID_);

		pNote->a_pk = a_pk;
		pNote->r = r;
		pNote->rho = rho;
		pNote->value = value;
		pNote->assetID = assetID;
	}

	EXPORT JSOutput* Jsoutput_Create()
	{
		return new JSOutput();
	}

	EXPORT void Jsoutput_Delete(JSOutput* pJsOutput)
	{
		delete pJsOutput;
	}

	EXPORT void Jsoutput_Init(JSOutput* pJsOutput, char* a_pk_, char* pk_enc_, CAmount value, char* memo, char* assetID_)
	{
		uint256 a_pk = ConvertFromBytesInv(a_pk_);
		uint256 pk_enc = ConvertFromBytesInv(pk_enc_);
		uint256 assetId = ConvertFromBytesInv(assetID_);

		pJsOutput->addr = PaymentAddress(a_pk, pk_enc);
		pJsOutput->value = value;
		pJsOutput->assetID = assetId;

		for (int i = 0; i < strlen(memo); i++)
		{
			pJsOutput->memo[i] = memo[i];
		}
	}

	//uint256 a_pk;
	//uint64_t value;
	//uint256 rho;
	//uint256 r;
	EXPORT void GetNullifier(char* a_pk_, char* rho_, char* r_, CAmount value, char* a_sk_, char* out_nullifier)
	{
		uint256 a_pk = ConvertFromBytesInv(a_pk_);
		uint256 rho = ConvertFromBytesInv(rho_);
		uint256 r = ConvertFromBytesInv(r_);

		Note nt = Note();
		nt.a_pk = a_pk;
		nt.r = r;
		nt.rho = rho;
		nt.value = value;

		uint256 sk_256 = ConvertFromBytes(a_sk_);
		uint252 sk_252 = uint252(sk_256);

		SpendingKey sk = SpendingKey(sk_252);

		JSInput input = JSInput();
		input.note = nt;
		input.key = sk;

		uint256 nullifier = input.nullifier();

		memcpy(out_nullifier, nullifier.begin(), 32);
	}
#ifdef __cplusplus
}
#endif