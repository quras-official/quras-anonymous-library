#pragma once
#include "../QurasModules/JoinSplit.h"

class JSDescription;

struct JSTransactionOutput { // 169
	char index;				// 0
	char AssetID[32];		// 1
	char Value[8];			// 33
	char a_pk[32];			// 41
	char pk_enc[32];		// 73
	char rho[32];			// 105
	char r[32];				// 137
};

extern QRJoinSplit* pqurasParams;

extern int QR_LoadParams(int nMode, char* vkPath, char* pkPath);
extern bool QR_LibffInit();
extern JSDescription* ConvertBytetoJSD(char* byte);
extern char* ConvertJSDtoByte(JSDescription jsd, int& num_bits);
extern char* g_FindMyNotes(char* jsdescription, char* private_key, char* join_split_pub_key);

extern uint256 ConvertFromBytes(char* arg);
extern uint256 ConvertFromBytesInv(char* arg);