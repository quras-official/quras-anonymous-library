#include "Address.h"
#include "NoteEncryption.h"
//#include "hash.h"
#include "prf.h"
//#include "streams.h"

namespace libquras {

	//uint256 PaymentAddress::GetHash() const {
	//	CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
	//	ss << *this;
	//	return Hash(ss.begin(), ss.end());
	//}

	uint256 ReceivingKey::pk_enc() const {
		return QRNoteEncryption::generate_pubkey(*this);
	}

	PaymentAddress ViewingKey::address() const {
		return PaymentAddress(a_pk, sk_enc.pk_enc());
	}

	ReceivingKey SpendingKey::receiving_key() const {
		return ReceivingKey(QRNoteEncryption::generate_privkey(*this));
	}

	ViewingKey SpendingKey::viewing_key() const {
		return ViewingKey(PRF_addr_a_pk(*this), receiving_key());
	}

	SpendingKey SpendingKey::random() {
		return SpendingKey(random_uint252());
	}

	PaymentAddress SpendingKey::address() const {
		return viewing_key().address();
	}

}
