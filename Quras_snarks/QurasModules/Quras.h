#pragma once
#define QR_NUM_JS_INPUTS 2
#define QR_NUM_JS_OUTPUTS 2
#define INCREMENTAL_MERKLE_TREE_DEPTH 29
#define INCREMENTAL_MERKLE_TREE_DEPTH_TESTING 4

#define QR_NOTEPLAINTEXT_LEADING 1
#define QR_V_SIZE 8
#define QR_RHO_SIZE 32
#define QR_R_SIZE 32
#define QR_MEMO_SIZE 512
#define QR_ASSET_ID_SIZE 32

#define QR_NOTEPLAINTEXT_SIZE (QR_NOTEPLAINTEXT_LEADING + QR_V_SIZE + QR_RHO_SIZE + QR_R_SIZE + QR_MEMO_SIZE + QR_ASSET_ID_SIZE)