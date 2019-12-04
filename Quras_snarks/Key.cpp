#include "AsyncJoinSplitInfo.h"
#include "QurasModules\transaction\transaction.h"
#include "common\global.h"

#ifdef __cplusplus    // If used by C++ code, 
extern "C" {          // we need to export the C interface
#endif

#define EXPORT extern __declspec( dllexport )
	
	EXPORT char* ReceivingKey_Pk_enc(char* receiving_key)
	{
		uint256 rk_256 = ConvertFromBytesInv(receiving_key);

		ReceivingKey rk = ReceivingKey(rk_256);
		
		uint256 pk_enc = rk.pk_enc();

		char* byRet = new char[pk_enc.size()];
		memcpy(byRet, pk_enc.begin(), pk_enc.size());

		return byRet;
	}

	EXPORT char* SpendingKey_ReceivingKey(char* spending_key)
	{
		uint256 sk_256 = ConvertFromBytes(spending_key);

		uint252 sk_252 = uint252(sk_256);
		SpendingKey sk = SpendingKey(sk_252);

		ReceivingKey rk = sk.receiving_key();

		char* byRet = new char[rk.size()];
		memcpy(byRet, rk.begin(), rk.size());

		return byRet;
	}

	EXPORT char* SpendingKey_Viewing_key(char* spending_key)
	{
		uint256 sk_256 = ConvertFromBytes(spending_key);

		uint252 sk_252 = uint252(sk_256);
		SpendingKey sk = SpendingKey(sk_252);

		ViewingKey vk = sk.viewing_key();

		char* byRet = new char[vk.a_pk.size() + vk.sk_enc.size()];

		memcpy(byRet, vk.a_pk.begin(), vk.a_pk.size());
		memcpy(byRet + vk.a_pk.size(), vk.sk_enc.begin(), vk.sk_enc.size());

		return byRet;
	}

	EXPORT char* SpendingKey_Address(char* spending_key)
	{
		uint256 sk_256 = ConvertFromBytes(spending_key);

		uint252 sk_252 = uint252(sk_256);
		SpendingKey sk = SpendingKey(sk_252);

		PaymentAddress pa = sk.address();

		char* byRet = new char[pa.a_pk.size() + pa.pk_enc.size()];

		memcpy(byRet, pa.a_pk.begin(), pa.a_pk.size());
		memcpy(byRet + pa.a_pk.size(), pa.pk_enc.begin(), pa.pk_enc.size());

		return byRet;
	}


#ifdef __cplusplus
}
#endif