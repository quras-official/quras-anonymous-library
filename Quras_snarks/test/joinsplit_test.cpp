#include "joinsplit_test.h"
#include "../common/global.h"
#include "../QurasModules/Quras.h"

#include "../QurasModules/JoinSplit.h"
#include "../QurasModules/transaction/transaction.h"
#include <libff\common\profiling.hpp>
#include "..\QurasModules\QurasCrypto.h"
#include "..\QurasModules\JoinSplit.h"

#include "..\QurasModules\crypto\common.h"
#include "..\QurasModules\random.h"
#include "..\QurasModules\proof.h"
#include "..\QurasModules\streams.h"
#include "..\QurasModules\utilstrencodings.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/function.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>


using namespace libquras;

char* ConvertJSDtoByte(JSDescription jsd)
{
	int jsd_length = 0;
	jsd_length += sizeof(CAmount);						//vpub_old
	jsd_length += sizeof(CAmount);						//vpub_new
	jsd_length += 32;									//anchor
	jsd_length += QR_NUM_JS_INPUTS * 32;				//nullifiers
	jsd_length += QR_NUM_JS_OUTPUTS * 32;				//commitments
	jsd_length += 32;									//ephermeralKey
	jsd_length += 32;									//randomSeed
	jsd_length += QR_NUM_JS_INPUTS * 32;				//macs
	jsd_length += jsd.proof.Size();						// proof size
	jsd_length += QR_NUM_JS_OUTPUTS * QRNoteEncryption::Ciphertext::size();

	char data[2000] = { 0 };
	char* ptr_data;
	ptr_data = data;
	memcpy(ptr_data, &jsd.vpub_old, sizeof(CAmount));
	ptr_data += sizeof(CAmount);
	memcpy(ptr_data, &jsd.vpub_new, sizeof(CAmount));
	ptr_data += sizeof(CAmount);
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
	return data;
}

void test_joinsplit()
{
	libff::start_profiling();

	// construct a proof.

	uint256 assetID = random_uint256();
	uint256 anchor = QRIncrementalMerkleTree().root();
	uint256 pubKeyHash;

	JSDescription jsdesc(*pqurasParams,
		pubKeyHash,
		anchor,
		{ JSInput(), JSInput() },
		{ JSOutput(), JSOutput() },
		0,
		0,
		assetID);

	ConvertJSDtoByte(jsdesc);
}

void test_note_encrypt()
{
	SpendingKey sk = SpendingKey::random();
	uint256 a_pk = sk.address().a_pk;

	libquras::Note nt;
	nt.a_pk = a_pk;
	nt.value = 100;
	nt.r = uint256();
	nt.rho = uint256();

	boost::array<unsigned char, QR_MEMO_SIZE> memo = boost::array<unsigned char, QR_MEMO_SIZE>();

	NotePlaintext pt(nt, memo);

	uint256 h_sig = uint256();
	QRNoteEncryption encryptor(h_sig);

	QRNoteEncryption::Ciphertext ciphertext = pt.encrypt(encryptor, sk.address().pk_enc);

	QRNoteDecryption decryptor(sk.viewing_key().sk_enc);

	auto note_pt = libquras::NotePlaintext::decrypt(
		decryptor,
		ciphertext,
		encryptor.get_epk(),
		h_sig,
		(unsigned char)0);
}

void test_address()
{
	char chPrivate[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	std::vector<unsigned char> buffer;

	buffer.clear();
	for (int i = 0; i < 32; i++)
	{
		buffer.push_back(chPrivate[i]);
	}
	
	uint256 sk_256 = uint256(buffer);
	uint252 sk_252 = uint252(sk_256);
	SpendingKey sk = SpendingKey(sk_252);

	PaymentAddress pa = sk.address();
}

int test_joinsplit_locals()
{
	// Joinsplit test
	auto verifier = libquras::ProofVerifier::Strict();

	// The recipient's information.
	SpendingKey recipient_key = SpendingKey::random();
	PaymentAddress recipient_addr = recipient_key.address();

	// Create the commitment tree
	QRIncrementalMerkleTree tree;

	// Set up a JoinSplit description
	uint256 ephemeralKey;
	uint256 randomSeed;
	uint64_t vpub_old = 10;
	uint64_t vpub_new = 0;
	uint256 pubKeyHash = random_uint256();
	boost::array<uint256, 2> macs;
	boost::array<uint256, 2> nullifiers;
	boost::array<uint256, 2> commitments;
	uint256 rt = tree.root();

	uint256 assetId = random_uint256();
	
	boost::array<QRNoteEncryption::Ciphertext, 2> ciphertexts;
	libquras::QRProof proof;

	{
		boost::array<JSInput, 2> inputs = {
			JSInput(assetId), // dummy input
			JSInput(assetId) // dummy input
		};

		boost::array<JSOutput, 2> outputs = {
			JSOutput(recipient_addr, 10, assetId),
			JSOutput(assetId) // dummy output
		};

		boost::array<Note, 2> output_notes;

		if (pqurasParams == NULL)
		{
			QR_LoadParams(1, "", "");
			QR_LoadParams(2, "", "");
		}

		// Perform the proof
		proof = pqurasParams->prove(
			inputs,
			outputs,
			output_notes,
			ciphertexts,
			ephemeralKey,
			pubKeyHash,
			randomSeed,
			macs,
			nullifiers,
			commitments,
			vpub_old,
			vpub_new,
			rt,
			assetId
		);
	}

	// Verify the transaction:
	if (!pqurasParams->verify(
		proof,
		verifier,
		pubKeyHash,
		randomSeed,
		macs,
		nullifiers,
		commitments,
		vpub_old,
		vpub_new,
		assetId,
		rt
	))
	{
		return -1;
	}

	
	auto h_sig = pqurasParams->h_sig(randomSeed, nullifiers, pubKeyHash);
	QRNoteDecryption decryptor(recipient_key.receiving_key());

	auto note_pt = NotePlaintext::decrypt(
	decryptor,
	ciphertexts[0],
	ephemeralKey,
	h_sig,
	0
	);

	auto decrypted_note = note_pt.note(recipient_addr);

	if (decrypted_note.value != 10)
	{
	return -1;
	}


	// Insert the commitments from the last tx into the tree

	tree.append(commitments[0]);
	auto witness_recipient = tree.witness();
	tree.append(commitments[1]);
	witness_recipient.append(commitments[1]);

	//auto witness_recipient = tree.witness();
	//tree.append(commitments[0]);
	//tree.append(commitments[1]);
	//witness_recipient.append(commitments[0]);
	//witness_recipient.append(commitments[1]);

	vpub_old = 0;
	vpub_new = 1;

	QRIncrementalMerkleTree tree_old;

	rt = tree.root();
	pubKeyHash = random_uint256();

	{
		boost::array<JSInput, 2> inputs = {
		JSInput(), // dummy input
		JSInput(witness_recipient, decrypted_note, recipient_key)
		};

		SpendingKey second_recipient = SpendingKey::random();
		PaymentAddress second_addr = second_recipient.address();

		boost::array<JSOutput, 2> outputs = {
		JSOutput(second_addr, 9, random_uint256()),
		JSOutput() // dummy output
		};

		boost::array<Note, 2> output_notes;

		// Perform the proof
		proof = pqurasParams->prove(
			inputs,
			outputs,
			output_notes,
			ciphertexts,
			ephemeralKey,
			pubKeyHash,
			randomSeed,
			macs,
			nullifiers,
			commitments,
			vpub_old,
			vpub_new,
			rt,
			assetId
		);

		if (!pqurasParams->verify(
			proof,
			verifier,
			pubKeyHash,
			randomSeed,
			macs,
			nullifiers,
			commitments,
			vpub_old,
			vpub_new,
			assetId,
			rt))
		{
			return -1;
		}

		return 0;
	}
	
}

int test_merkle_tree()
{
	// Insert anchor into base.
	QRIncrementalMerkleTree tree;
	QRIncrementalMerkleTree t1, t2, t3;
	QRIncrementalWitness w1;

	uint256 cm = GetRandHash();
	uint256 cm1 = GetRandHash();
	uint256 cm2 = GetRandHash();
	uint256 cm3 = GetRandHash();
	uint256 cm4 = GetRandHash();

	t1.append(cm);
	t1.append(cm1);
	t1.append(cm2);

	t3 = t1;


	t1.append(cm3);
	t1.append(cm4);

	t2.append(cm);
	t2.append(cm1);
	t2.append(cm2);
	t2.append(cm3);
	t2.append(cm4);

	uint256 rt1 = t1.root();

	uint256 rt2 = t2.root();

	tree.append(cm);


	tree.append(cm1);


	tree.append(cm2);

	QRIncrementalWitness w = tree.witness();
	QRIncrementalWitness w_test = tree.witness();

	uint256 old_root = tree.root();


	tree.append(cm3);
	w.append(cm3);
	w_test.append(cm3);


	tree.append(cm4);
	w.append(cm4);
	w_test.append(cm4);


	uint256 witness = w.element();



	uint256 rt = tree.root();
	uint256 wrt = w.root();

	MerklePath path = w.path();
	MerklePath wtestPath = w_test.path();

	CDataStream sspath(SER_NETWORK, 1);
	sspath << path;

	std::string hexp = sspath.str();

	CDataStream tsspath(SER_NETWORK, 1);
	tsspath << wtestPath;
	std::string hexpt = tsspath.str();

	bool same = false;
	if (hexp == hexpt)
	{
	same = true;
	}

	CDataStream ss(SER_NETWORK, 1);
	ss << tree;

	std::string hex = ss.str();

	QRIncrementalMerkleTree tree_new;

	ss >> tree_new;


	CDataStream ss1(hex.c_str(), hex.c_str() + hex.length(), SER_NETWORK, 1);

	QRIncrementalMerkleTree tree_save;
	ss1 >> tree_save;

	return 0;
}

void test_genereate_key()
{
	printf("Starting generation of keys\n");

	JoinSplit<2, 2>::Generate("crypto//r1cs.key", "crypto//vk.key", "crypto//pk.key");

	printf("Finished generation of keys\n");
}

void test_generate_key_by_constraint()
{
	printf("Starting generation of keys\n");

	JoinSplit<2, 2>::GenerateByConstraint( "crypto//constraint.key", "crypto//vk.key", "crypto//pk.key");

	printf("Finished generation of keys\n");
}

void test_generate_key(uint256 seedKey)
{
	printf("Starting generation of keys\n");

	JoinSplit<2, 2>::Generate(seedKey, "crypto//r1cs.key", "crypto//vk.key", "crypto//pk.key");

	printf("Finished generation of keys\n");
}

void generate_constraint_file(uint256 seedKey, int nStart, int nSize)
{
	printf("Starting generation of keys\n");

	JoinSplit<2, 2>::GenerateConstraint("crypto//constraint.key", seedKey, nStart, nSize);

	printf("Finishing generation of keys\n");
}

bool verify_constraint_file(std::string path, int nSize)
{
	printf("Verfiying Constraints\n");

	bool verified = JoinSplit<2, 2>::VerifyConstraint(path, nSize);
	printf("%d", verified);
	return verified;
}
