#include "transaction.h"

#include "../hash.h"
#include "../tinyformat.h"
#include "../utilstrencodings.h"

JSDescription::JSDescription(QRJoinSplit& params,
	const uint256& pubKeyHash,
	const uint256& anchor,
	const boost::array<libquras::JSInput, QR_NUM_JS_INPUTS>& inputs,
	const boost::array<libquras::JSOutput, QR_NUM_JS_OUTPUTS>& outputs,
	CAmount vpub_old,
	CAmount vpub_new,
	const uint256 assetID,
	bool computeProof,
	uint256 *esk // payment disclosure
) : vpub_old(vpub_old), vpub_new(vpub_new), anchor(anchor), Asset_Id(assetID)
{
	boost::array<libquras::Note, QR_NUM_JS_OUTPUTS> notes;

	proof = params.prove(
		inputs,
		outputs,
		notes,
		ciphertexts,
		ephemeralKey,
		pubKeyHash,
		randomSeed,
		macs,
		nullifiers,
		commitments,
		vpub_old,
		vpub_new,
		anchor,
		assetID,
		computeProof,
		esk // payment disclosure
	);
}

JSDescription JSDescription::Randomized(
	QRJoinSplit& params,
	const uint256& pubKeyHash,
	const uint256& anchor,
	boost::array<libquras::JSInput, QR_NUM_JS_INPUTS>& inputs,
	boost::array<libquras::JSOutput, QR_NUM_JS_OUTPUTS>& outputs,
	boost::array<size_t, QR_NUM_JS_INPUTS>& inputMap,
	boost::array<size_t, QR_NUM_JS_OUTPUTS>& outputMap,
	CAmount vpub_old,
	CAmount vpub_new,
	const uint256 assetID,
	bool computeProof,
	uint256 *esk, // payment disclosure
	std::function<int(int)> gen
)
{
	// Randomize the order of the inputs and outputs
	inputMap = { 0, 1 };
	outputMap = { 0, 1 };

	assert(gen);

	MappedShuffle(inputs.begin(), inputMap.begin(), QR_NUM_JS_INPUTS, gen);
	MappedShuffle(outputs.begin(), outputMap.begin(), QR_NUM_JS_OUTPUTS, gen);

	return JSDescription(
		params, pubKeyHash, anchor, inputs, outputs,
		vpub_old, vpub_new, assetID, computeProof,
		esk // payment disclosure
	);
}

bool JSDescription::Verify(
	QRJoinSplit& params,
	libquras::ProofVerifier& verifier,
	const uint256& pubKeyHash
) const {
	return params.verify(
		proof,
		verifier,
		pubKeyHash,
		randomSeed,
		macs,
		nullifiers,
		commitments,
		vpub_old,
		vpub_new,
		Asset_Id,
		anchor
	);
}

uint256 JSDescription::h_sig(QRJoinSplit& params, const uint256& pubKeyHash) const
{
	return params.h_sig(randomSeed, nullifiers, pubKeyHash);
}