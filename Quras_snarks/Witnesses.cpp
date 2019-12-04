#include "AsyncJoinSplitInfo.h"
#include "QurasModules\transaction\transaction.h"
#include "common\global.h"

#ifdef __cplusplus    // If used by C++ code, 
extern "C" {          // we need to export the C interface
#endif

#define EXPORT extern __declspec( dllexport )

	EXPORT std::vector<boost::optional < QRIncrementalWitness>> * Witnesses_Create()
	{
		std::vector<boost::optional < QRIncrementalWitness>> * w = new std::vector<boost::optional < QRIncrementalWitness>>();
		return w;
	}

	EXPORT void Witnesses_Add(std::vector<boost::optional < QRIncrementalWitness>> * w, QRIncrementalWitness* witness)
	{
		w->push_back(*witness);
	}
	
	EXPORT void Witnesses_Clear(std::vector<boost::optional < QRIncrementalWitness>> * w)
	{
		w->clear();
	}
#ifdef __cplusplus
}
#endif