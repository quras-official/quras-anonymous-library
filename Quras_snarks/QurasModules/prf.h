#pragma once

#include "uint256.h"
#include "uint252.h"

uint256 PRF_addr_a_pk(const uint252& a_sk);
uint256 PRF_addr_sk_enc(const uint252& a_sk);
uint256 PRF_nf(const uint252& a_sk, const uint256& rho);
uint256 PRF_pk(const uint252& a_sk, size_t i0, const uint256& h_sig);
uint256 PRF_rho(const uint252& phi, size_t i0, const uint256& h_sig);