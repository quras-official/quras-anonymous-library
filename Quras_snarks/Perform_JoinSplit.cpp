#include "AsyncJoinSplitInfo.h"
#include "QurasModules\transaction\transaction.h"
#include "common\global.h"

#ifdef __cplusplus    // If used by C++ code, 
extern "C" {          // we need to export the C interface
#endif

#define EXPORT extern __declspec( dllexport )


	EXPORT char* Perform_joinsplit_All(AsyncJoinSplitInfo* pAsyncJSI,
		std::vector<boost::optional < QRIncrementalWitness>> witnesses,
		uint256 anchor,
		uint256 joinSplitPubKey_,
		char* jsprivkey, 
		int& num_bits,
		SpendingKey spendingkey_)
	{
		if (anchor.IsNull()) {
			throw std::runtime_error("anchor is null");
		}

		if (!(witnesses.size() == pAsyncJSI->notes.size())) {
			throw std::runtime_error("number of notes and witnesses do not match");
		}

		for (size_t i = 0; i < witnesses.size(); i++) {
			if (!witnesses[i]) {
				throw std::runtime_error("joinsplit input could not be found in tree");
			}
			pAsyncJSI->vjsin.push_back(JSInput(*witnesses[i], pAsyncJSI->notes[i], spendingkey_));
		}

		// Make sure there are two inputs and two outputs
		while (pAsyncJSI->vjsin.size() < QR_NUM_JS_INPUTS) {
			pAsyncJSI->vjsin.push_back(JSInput(pAsyncJSI->AssetID));
		}

		while (pAsyncJSI->vjsout.size() < QR_NUM_JS_OUTPUTS) {
			pAsyncJSI->vjsout.push_back(JSOutput(pAsyncJSI->AssetID));
		}

		if (pAsyncJSI->vjsout.size() != QR_NUM_JS_INPUTS || pAsyncJSI->vjsin.size() != QR_NUM_JS_OUTPUTS) {
			throw std::runtime_error("unsupported joinsplit input/output counts");
		}

		// Generate the proof, this can take over a minute.
		boost::array<JSInput, QR_NUM_JS_INPUTS> inputs
		{ pAsyncJSI->vjsin[0], pAsyncJSI->vjsin[1] };
		boost::array<JSOutput, QR_NUM_JS_OUTPUTS> outputs
		{ pAsyncJSI->vjsout[0], pAsyncJSI->vjsout[1] };
		boost::array<size_t, QR_NUM_JS_INPUTS> inputMap;
		boost::array<size_t, QR_NUM_JS_OUTPUTS> outputMap;

		uint256 esk; // payment disclosure - secret

		JSDescription jsdesc = JSDescription::Randomized(
			*pqurasParams,
			joinSplitPubKey_,
			anchor,
			inputs,
			outputs,
			inputMap,
			outputMap,
			pAsyncJSI->vpub_old,
			pAsyncJSI->vpub_new,
			pAsyncJSI->AssetID,
			true,
			&esk); // parameter expects pointer to esk, so pass in address
		{
			auto verifier = libquras::ProofVerifier::Strict();
			if (!(jsdesc.Verify(*pqurasParams, verifier, joinSplitPubKey_))) {
				throw std::runtime_error("error verifying joinsplit");
			}
		}

		jsdesc.Asset_Id = pAsyncJSI->AssetID;

		return ConvertJSDtoByte(jsdesc, num_bits);
	}

	EXPORT char* Perform_joinsplit(AsyncJoinSplitInfo* pAsyncJSI, char* jspubkey, char* jsprivkey, int* out_length, char* spendingKey, char* byAnchor, std::vector<boost::optional < QRIncrementalWitness>> * w)
	{
		uint256 sk_256 = ConvertFromBytes(spendingKey);
		uint252 sk_252 = uint252(sk_256);

		SpendingKey sk = SpendingKey(sk_252);

		uint256 anchor = ConvertFromBytesInv(byAnchor);

		uint256 joinsplit_pubkey = ConvertFromBytes(jspubkey);

		int num_bits = 0;
		char * byRet = Perform_joinsplit_All(pAsyncJSI, *w, anchor, joinsplit_pubkey, jsprivkey, num_bits, sk);
		
		out_length[0] = num_bits;
		return byRet;
	}

	EXPORT bool JSVerify(char* jsdescription, char* jspubkey)
	{
		uint256 joinsplit_pubkey = ConvertFromBytes(jspubkey);

		JSDescription* jsd = ConvertBytetoJSD(jsdescription);

		if (pqurasParams == NULL)
		{
			QR_LoadParams(1, "", "");
		}

		auto verifier = libquras::ProofVerifier::Strict();
		if (!(jsd->Verify(*pqurasParams, verifier, joinsplit_pubkey))) {
			//throw std::runtime_error("error verifying joinsplit");
			return false;
		}
		return true;
	}

	EXPORT void FreeMemory(void* memory)
	{
		delete memory;
	}

	EXPORT char* FindMyNotes(char* jsdescription, char* private_key, char* join_split_pub_key)
	{
		return g_FindMyNotes(jsdescription, private_key, join_split_pub_key);
	}

#ifdef __cplusplus
}
#endif