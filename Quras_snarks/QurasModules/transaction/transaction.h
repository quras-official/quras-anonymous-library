#pragma once
#include "../amount.h"
#include "../random.h"
#include "../serialize.h"
#include "../uint256.h"

#include <boost/array.hpp>

#include "../NoteEncryption.h"
#include "../Quras.h"
#include "../JoinSplit.h"
#include "../Proof.h"

class JSDescription
{
public:
	// These values 'enter from' and 'exit to' the value
	// pool, respectively.
	CAmount vpub_old;
	CAmount vpub_new;

	// Asset ID

	uint256 Asset_Id;

	// JoinSplits are always anchored to a root in the note
	// commitment tree at some point in the blockchain
	// history or in the history of the current
	// transaction.
	uint256 anchor;

	// Nullifiers are used to prevent double-spends. They
	// are derived from the secrets placed in the note
	// and the secret spend-authority key known by the
	// spender.
	boost::array<uint256, QR_NUM_JS_INPUTS> nullifiers;

	// Note commitments are introduced into the commitment
	// tree, blinding the public about the values and
	// destinations involved in the JoinSplit. The presence of
	// a commitment in the note commitment tree is required
	// to spend it.
	boost::array<uint256, QR_NUM_JS_OUTPUTS> commitments;

	// Ephemeral key
	uint256 ephemeralKey;

	// Ciphertexts
	// These contain trapdoors, values and other information
	// that the recipient needs, including a memo field. It
	// is encrypted using the scheme implemented in crypto/NoteEncryption.cpp
	boost::array<QRNoteEncryption::Ciphertext, QR_NUM_JS_OUTPUTS> ciphertexts = { { { { 0 } } } };

	// Random seed
	uint256 randomSeed;

	// MACs
	// The verification of the JoinSplit requires these MACs
	// to be provided as an input.
	boost::array<uint256, QR_NUM_JS_INPUTS> macs;

	// JoinSplit proof
	// This is a zk-SNARK which ensures that this JoinSplit is valid.
	libquras::QRProof proof;

	JSDescription() : vpub_old(0), vpub_new(0) { }

	JSDescription(QRJoinSplit& params,
		const uint256& pubKeyHash,
		const uint256& rt,
		const boost::array<libquras::JSInput, QR_NUM_JS_INPUTS>& inputs,
		const boost::array<libquras::JSOutput, QR_NUM_JS_OUTPUTS>& outputs,
		CAmount vpub_old,
		CAmount vpub_new,
		const uint256 assetID,
		bool computeProof = true, // Set to false in some tests
		uint256 *esk = nullptr // payment disclosure
	);

	static JSDescription Randomized(
		QRJoinSplit& params,
		const uint256& pubKeyHash,
		const uint256& rt,
		boost::array<libquras::JSInput, QR_NUM_JS_INPUTS>& inputs,
		boost::array<libquras::JSOutput, QR_NUM_JS_OUTPUTS>& outputs,
		boost::array<size_t, QR_NUM_JS_INPUTS>& inputMap,
		boost::array<size_t, QR_NUM_JS_OUTPUTS>& outputMap,
		CAmount vpub_old,
		CAmount vpub_new,
		const uint256 assetID,
		bool computeProof = true, // Set to false in some tests
		uint256 *esk = nullptr, // payment disclosure
		std::function<int(int)> gen = GetRandInt
	);

	// Verifies that the JoinSplit proof is correct.
	bool Verify(
		QRJoinSplit& params,
		libquras::ProofVerifier& verifier,
		const uint256& pubKeyHash
	) const;

	// Returns the calculated h_sig
	uint256 h_sig(QRJoinSplit& params, const uint256& pubKeyHash) const;

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(vpub_old);
		READWRITE(vpub_new);
		READWRITE(anchor);
		READWRITE(nullifiers);
		READWRITE(commitments);
		READWRITE(ephemeralKey);
		READWRITE(randomSeed);
		READWRITE(macs);
		READWRITE(proof);
		READWRITE(ciphertexts);
	}

	friend bool operator==(const JSDescription& a, const JSDescription& b)
	{
		return (
			a.vpub_old == b.vpub_old &&
			a.vpub_new == b.vpub_new &&
			a.anchor == b.anchor &&
			a.nullifiers == b.nullifiers &&
			a.commitments == b.commitments &&
			a.ephemeralKey == b.ephemeralKey &&
			a.ciphertexts == b.ciphertexts &&
			a.randomSeed == b.randomSeed &&
			a.macs == b.macs &&
			a.proof == b.proof
			);
	}

	friend bool operator!=(const JSDescription& a, const JSDescription& b)
	{
		return !(a == b);
	}
};

