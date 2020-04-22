#pragma once
#include "Quras.h"
#include "proof.h"
#include "Address.h"
#include "Note.h"
#include "IncrementalMerkleTree.h"
#include "NoteEncryption.h"

#include "uint256.h"
#include "uint252.h"

#include <boost/array.hpp>

namespace libquras {

	class JSInput {
	public:
		QRIncrementalWitness witness;
		Note note;
		SpendingKey key;

		JSInput();
		JSInput(uint256 assetID);
		JSInput(QRIncrementalWitness witness,
			Note note,
			SpendingKey key) : witness(witness), note(note), key(key) { }

		uint256 nullifier() const {
			return note.nullifier(key);
		}
	};

	class JSOutput {
	public:
		PaymentAddress addr;
		uint64_t value;
		uint256 assetID;
		boost::array<unsigned char, QR_MEMO_SIZE> memo = { { 0xF6 } };  // 0xF6 is invalid UTF8 as per spec, rest of array is 0x00

		JSOutput();
		JSOutput(uint256 assetID);
		JSOutput(PaymentAddress addr, uint64_t value, uint256 assetID) : addr(addr), value(value), assetID(assetID) { }

		Note note(const uint252& phi, const uint256& r, size_t i, const uint256& h_sig) const;
	};

	template<size_t NumInputs, size_t NumOutputs>
	class JoinSplit {
	public:
		virtual ~JoinSplit() {}

		static void Generate(const std::string r1csPath,
			const std::string vkPath,
			const std::string pkPath);
		static void Generate(uint256 seedHash,
			const std::string r1csPath,
			const std::string vkPath,
			const std::string pkPath);
		static JoinSplit<NumInputs, NumOutputs>* Prepared(const std::string vkPath,
			const std::string pkPath);

		static uint256 h_sig(const uint256& randomSeed,
			const boost::array<uint256, NumInputs>& nullifiers,
			const uint256& pubKeyHash
		);

		virtual bool LoadPk(std::string pkPath) = 0;

		virtual QRProof prove(
			const boost::array<JSInput, NumInputs>& inputs,
			const boost::array<JSOutput, NumOutputs>& outputs,
			boost::array<Note, NumOutputs>& out_notes,
			boost::array<QRNoteEncryption::Ciphertext, NumOutputs>& out_ciphertexts,
			uint256& out_ephemeralKey,
			const uint256& pubKeyHash,
			uint256& out_randomSeed,
			boost::array<uint256, NumInputs>& out_hmacs,
			boost::array<uint256, NumInputs>& out_nullifiers,
			boost::array<uint256, NumOutputs>& out_commitments,
			uint64_t vpub_old,
			uint64_t vpub_new,
			const uint256& rt,
			uint256 assetID,
			bool computeProof = true,
			// For paymentdisclosure, we need to retrieve the esk.
			// Reference as non-const parameter with default value leads to compile error.
			// So use pointer for simplicity.
			uint256 *out_esk = nullptr
		) = 0;

		virtual bool verify(
			const QRProof& proof,
			ProofVerifier& verifier,
			const uint256& pubKeyHash,
			const uint256& randomSeed,
			const boost::array<uint256, NumInputs>& hmacs,
			const boost::array<uint256, NumInputs>& nullifiers,
			const boost::array<uint256, NumOutputs>& commitments,
			uint64_t vpub_old,
			uint64_t vpub_new,
			uint256 assetID,
			const uint256& rt
		) = 0;

	protected:
		JoinSplit() {}
	};

}

typedef libquras::JoinSplit<QR_NUM_JS_INPUTS, QR_NUM_JS_OUTPUTS> QRJoinSplit;