#pragma once
#include "../QurasModules/uint256.h"

void test_joinsplit();
void test_note_encrypt();
void test_address();
int test_joinsplit_locals();

int test_merkle_tree();

void test_genereate_key();
void test_generate_key(uint256 seedKey);

void test_generate_key_by_constraint();

void generate_constraint_file(uint256 seedKey, int nStart, int nSize);

bool verify_constraint_file(std::string path, int nSize);