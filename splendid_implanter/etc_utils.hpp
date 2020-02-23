#pragma once
#include <codecvt>
#include <string>
#include <mutex>

#define CALL_ONCE(x) \
{\
static std::once_flag flag;\
std::call_once(flag, x);\
}\

namespace impl
{
	inline std::wstring_convert< std::codecvt_utf8_utf16<wchar_t> > converter{ };

	__forceinline std::wstring to_utf16( const std::string& utf8 )
	{
		return converter.from_bytes( utf8 );
	}

	__forceinline std::string to_utf8( const std::wstring& utf16 )
	{
		return converter.to_bytes( utf16 );
	}
}