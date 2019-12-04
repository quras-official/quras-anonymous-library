#include "timedata.h"

//#include "netbase.h"
#include "sync.h"
#include "utils/util.h"
#include "utilstrencodings.h"
#include "utils\utiltime.h"

#include <boost/foreach.hpp>

using namespace std;

static CCriticalSection cs_nTimeOffset;
static int64_t nTimeOffset = 0;

/**
* "Never go to sea with two chronometers; take one or three."
* Our three time sources are:
*  - System clock
*  - Median of other nodes clocks
*  - The user (asking the user to fix the system clock if the first two disagree)
*/
int64_t GetTimeOffset()
{
	LOCK(cs_nTimeOffset);
	return nTimeOffset;
}

int64_t GetAdjustedTime()
{
	return GetTime() + GetTimeOffset();
}

static int64_t abs64(int64_t n)
{
	return (n >= 0 ? n : -n);
}

#define BITCOIN_TIMEDATA_MAX_SAMPLES 200

void AddTimeData(const CNetAddr& ip, int64_t nOffsetSample)
{
}
