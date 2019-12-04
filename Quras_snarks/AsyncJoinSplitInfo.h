#pragma once
#include "QurasModules\JoinSplit.h"
#include "QurasModules\amount.h"

using namespace libquras;

struct AsyncJoinSplitInfo
{
	std::vector<JSInput> vjsin;
	std::vector<JSOutput> vjsout;
	std::vector<Note> notes;
	CAmount vpub_old = 0;
	CAmount vpub_new = 0;
	uint256 AssetID;
};

