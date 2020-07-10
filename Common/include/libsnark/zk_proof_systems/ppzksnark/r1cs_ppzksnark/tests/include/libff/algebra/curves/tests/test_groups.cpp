/**
 *****************************************************************************
 * @author     This file is part of libff, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#include <libff/common/profiling.hpp>
#ifdef CURVE_BN128
#include <libff/algebra/curves/bn128/bn128_pp.hpp>
#endif
#include <sstream>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

using namespace libff;

template<typename GroupT>
void test_mixed_add()
{
    GroupT base, el, result;

    base = GroupT::zero();
    el = GroupT::zero();
    el.to_special();
    result = base.mixed_add(el);
    assert_except(result == base + el);

    base = GroupT::zero();
    el = GroupT::random_element();
    el.to_special();
    result = base.mixed_add(el);
    assert_except(result == base + el);

    base = GroupT::random_element();
    el = GroupT::zero();
    el.to_special();
    result = base.mixed_add(el);
    assert_except(result == base + el);

    base = GroupT::random_element();
    el = GroupT::random_element();
    el.to_special();
    result = base.mixed_add(el);
    assert_except(result == base + el);

    base = GroupT::random_element();
    el = base;
    el.to_special();
    result = base.mixed_add(el);
    assert_except(result == base.dbl());
}

template<typename GroupT>
void test_group()
{
    bigint<1> rand1 = bigint<1>("76749407");
    bigint<1> rand2 = bigint<1>("44410867");
    bigint<1> randsum = bigint<1>("121160274");

    GroupT zero = GroupT::zero();
    assert_except(zero == zero);
    GroupT one = GroupT::one();
    assert_except(one == one);
    GroupT two = bigint<1>(2l) * GroupT::one();
    assert_except(two == two);
    GroupT five = bigint<1>(5l) * GroupT::one();

    GroupT three = bigint<1>(3l) * GroupT::one();
    GroupT four = bigint<1>(4l) * GroupT::one();

    assert_except(two+five == three+four);

    GroupT a = GroupT::random_element();
    GroupT b = GroupT::random_element();

    assert_except(one != zero);
    assert_except(a != zero);
    assert_except(a != one);

    assert_except(b != zero);
    assert_except(b != one);

    assert_except(a.dbl() == a + a);
    assert_except(b.dbl() == b + b);
    assert_except(one.add(two) == three);
    assert_except(two.add(one) == three);
    assert_except(a + b == b + a);
    assert_except(a - a == zero);
    assert_except(a - b == a + (-b));
    assert_except(a - b == (-b) + a);

    // handle special cases
    assert_except(zero + (-a) == -a);
    assert_except(zero - a == -a);
    assert_except(a - zero == a);
    assert_except(a + zero == a);
    assert_except(zero + a == a);

    assert_except((a + b).dbl() == (a + b) + (b + a));
    assert_except(bigint<1>("2") * (a + b) == (a + b) + (b + a));

    assert_except((rand1 * a) + (rand2 * a) == (randsum * a));

    assert_except(GroupT::order() * a == zero);
    assert_except(GroupT::order() * one == zero);
    assert_except((GroupT::order() * a) - a != zero);
    assert_except((GroupT::order() * one) - one != zero);

    test_mixed_add<GroupT>();
}

template<typename GroupT>
void test_mul_by_q()
{
    GroupT a = GroupT::random_element();
    assert_except((GroupT::base_field_char()*a) == a.mul_by_q());
}

template<typename GroupT>
void test_output()
{
    GroupT g = GroupT::zero();

    for (size_t i = 0; i < 1000; ++i)
    {
        std::stringstream ss;
        ss << g;
        GroupT gg;
        ss >> gg;
        assert_except(g == gg);
        /* use a random point in next iteration */
        g = GroupT::random_element();
    }
}

int main(void)
{
    edwards_pp::init_public_params();
    test_group<G1<edwards_pp> >();
    test_output<G1<edwards_pp> >();
    test_group<G2<edwards_pp> >();
    test_output<G2<edwards_pp> >();
    test_mul_by_q<G2<edwards_pp> >();

    mnt4_pp::init_public_params();
    test_group<G1<mnt4_pp> >();
    test_output<G1<mnt4_pp> >();
    test_group<G2<mnt4_pp> >();
    test_output<G2<mnt4_pp> >();
    test_mul_by_q<G2<mnt4_pp> >();

    mnt6_pp::init_public_params();
    test_group<G1<mnt6_pp> >();
    test_output<G1<mnt6_pp> >();
    test_group<G2<mnt6_pp> >();
    test_output<G2<mnt6_pp> >();
    test_mul_by_q<G2<mnt6_pp> >();

    alt_bn128_pp::init_public_params();
    test_group<G1<alt_bn128_pp> >();
    test_output<G1<alt_bn128_pp> >();
    test_group<G2<alt_bn128_pp> >();
    test_output<G2<alt_bn128_pp> >();
    test_mul_by_q<G2<alt_bn128_pp> >();

#ifdef CURVE_BN128       // BN128 has fancy dependencies so it may be disabled
    bn128_pp::init_public_params();
    test_group<G1<bn128_pp> >();
    test_output<G1<bn128_pp> >();
    test_group<G2<bn128_pp> >();
    test_output<G2<bn128_pp> >();
#endif
}
