
#ifndef ASSERT_EXCEPT
inline void assert_except(bool condition)
{
	if (!condition)
	{
		throw std::runtime_error("Assertion failed to run.");
	}
}
#endif // !ASSERT_EXCEPT

#define ASSERT_EXCEPT