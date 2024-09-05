#ifndef __MOCK_SEV_COMMON_HPP__
#define __MOCK_SEV_COMMON_HPP__

#define MOCK_STR "0123456789abcdef"
#define set_mock_str(x) memcpy(x, MOCK_STR, sizeof(MOCK_STR))
#define check_mock_str(x) memcmp(x, MOCK_STR, sizeof(MOCK_STR))

#endif // !__MOCK_SEV_COMMON_HPP__
