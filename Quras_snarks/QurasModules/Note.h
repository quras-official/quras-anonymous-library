#pragma once

#include "uint256.h"
#include "Quras.h"
#include "Address.h"
#include "NoteEncryption.h"

namespace libquras {

	class Note {
	public:
		uint256 a_pk;
		uint64_t value;
		uint256 rho;
		uint256 r;
		uint256 assetID;

		Note(uint256 a_pk, uint64_t value, uint256 rho, uint256 r, uint256 assetID)
			: a_pk(a_pk), value(value), rho(rho), r(r), assetID(assetID) {}

		Note();

		uint256 cm() const;
		uint256 nullifier(const SpendingKey& a_sk) const;
	};

	class NotePlaintext {
	public:
		uint64_t value = 0;
		uint256 rho;
		uint256 r;
		uint256 assetID;
		boost::array<unsigned char, QR_MEMO_SIZE> memo;

		NotePlaintext() {}

		NotePlaintext(const Note& note, boost::array<unsigned char, QR_MEMO_SIZE> memo);

		Note note(const PaymentAddress& addr) const;

		ADD_SERIALIZE_METHODS;

		template <typename Stream, typename Operation>
		inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
			unsigned char leadingByte = 0x00;
			READWRITE(leadingByte);

			if (leadingByte != 0x00) {
				throw std::ios_base::failure("lead byte of NotePlaintext is not recognized");
			}

			READWRITE(value);
			READWRITE(rho);
			READWRITE(r);
			READWRITE(memo);
			READWRITE(assetID);
		}

		static NotePlaintext decrypt(const QRNoteDecryption& decryptor,
			const QRNoteDecryption::Ciphertext& ciphertext,
			const uint256& ephemeralKey,
			const uint256& h_sig,
			unsigned char nonce
		);

		QRNoteEncryption::Ciphertext encrypt(QRNoteEncryption& encryptor,
			const uint256& pk_enc
		) const;
	};

}