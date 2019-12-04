#pragma once
#include <boost\array.hpp>

class QRProof;
class uint252;
class uint256;

/*
QRProof getProve(uint252 phi, uint256 rt, uint256 h_sig, 
				const boost::array<JSInput, NumInputs>& inputs, 
				boost::array<Note, NumOutputs>& out_notes,
				uint64_t vpub_old,
				uint64_t vpub_new);

				*/