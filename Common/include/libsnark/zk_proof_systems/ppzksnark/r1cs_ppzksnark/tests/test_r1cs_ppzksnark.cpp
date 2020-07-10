/** @file
 *****************************************************************************
 Test program that exercises the ppzkSNARK (first generator, then
 prover, then verifier) on a synthetic R1CS instance.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>

using namespace libsnark;

template<typename ppT>
void test_r1cs_ppzksnark(size_t num_constraints,
                         size_t input_size)
{
    libff::print_header("(enter) Test R1CS ppzkSNARK");

    const bool test_serialization = true;
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    const bool bit = run_r1cs_ppzksnark<ppT>(example, test_serialization);
    assert_except(bit);

    libff::print_header("(leave) Test R1CS ppzkSNARK");
}

int main()
{
	printf("unsigned long long : 0x%jx\n", sizeof(unsigned long));
	printf("unsigned long long : 0x%jx\n", sizeof(unsigned long long));
	printf("unsigned int : %d\n", sizeof(unsigned int));
	printf("unsigned double : 0x%jx\n", sizeof(double));
	printf("unsigned float : 0x%jx\n", sizeof(float));

	unsigned long abc = -5;
	printf("abc : %d", abc);

	for (int i = 0; i < 64; i++) {
		size_t aa = (size_t)1u << i;
		size_t bb = (__int64)1u << i;

		if (aa != bb) {
			printf("%d, 0x%jx, 0x%jx", i, aa, bb);
		}
	}

	double ttt = -0xFFFFFFFFFFFFFFF;
	signed long long ttt1 = -0xFFFFFFFFFFFFFFF;
	printf("double %lf\n", ttt);
	printf("int64 %d\n", ttt1);

	unsigned long long int aa[4] = { 0x1111111111111111, 0x1111111111111111, 0x1111111111111111, 0x1111111111111111 };
	unsigned long long int bb[4] = { 0x1111111111111111, 0x1111111111111111, 0x1111111111111111, 0x1111111111111111 };

	mp_size_t size = 0;

	printf("mp_size_t : 0x%jx\n", size);

	mpn_gcdext(aa, bb, &size, aa, 4, bb, 4);
	
    default_r1cs_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    test_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(1, 1);
}
