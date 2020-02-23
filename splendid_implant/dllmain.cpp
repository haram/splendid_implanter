#include <Windows.h>

bool DllMain( void*, DWORD call_reason, void* )
{
	if ( call_reason != DLL_PROCESS_ATTACH )
		return false;

	MessageBoxA( nullptr, "hello world", "secret.club", MB_OK );

	return true;
}

extern "C" __declspec( dllexport )
LRESULT wnd_hk( int code, WPARAM wparam, LPARAM lparam )
{
	// handle race condition from calling hook multiple times
	static auto done_once = false;

	const auto pmsg = reinterpret_cast< MSG* >( lparam );

	if ( !done_once && pmsg->message == 0x5b0 )
	{
		UnhookWindowsHookEx( reinterpret_cast< HHOOK >( lparam ) );
		done_once = true;
	}

	// call next hook in queue
	return CallNextHookEx( nullptr, code, wparam, lparam );
}