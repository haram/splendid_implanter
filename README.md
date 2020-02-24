## Splendid Implanter

BattlEye compatible injector, done completely from user-mode.

## Usage

1. Run build.bat (this will only work for VS19, or VS17)
2. Start an elevated commandline
3. Go to the x64/Release directory
4. splendid_implanter.exe dll_name window_class

In this case: `splendid_implanter.exe splendid_implant.dll R6Game`

To find the window's class name, use winlister.

## Details

This exploits a flaw in the user-mode component of BattlEye that should've never even existed to begin with.

By hooking CreateFileW, and checking if the lpFileName parameter contains our file's name then manipulating it to believe that Kernel32.dll is being loaded, we pass their dll checks and land our module inside of it as if it's a legitimate module.

The name is a play on Perfect Injector, don't mind that.

## Example

Every injectable library must have an export called "wnd_hk" that handles the WH, then calls the next in queue.

```cpp
extern "C" __declspec( dllexport )
LRESULT wnd_hk( int32_t code, WPARAM wparam, LPARAM lparam )
{
	// handle race condition from calling hook multiple times
	static auto done_once = false;

	const auto pmsg = reinterpret_cast< MSG* >( lparam );

	if ( !done_once && pmsg->message == 0x5b0 )
	{
		UnhookWindowsHookEx( reinterpret_cast< HHOOK >( lparam ) );
		
		// initialization here
		
		done_once = true;
	}

	// call next hook in queue
	return CallNextHookEx( nullptr, code, wparam, lparam );
}
```

splendid_implant is a ready-to-inject example for R6:S that'll enable player icons once in-game.

## Features

support for:

- thread creation
- seh, c++ exceptions
- raw detouring without any tricks
- doing literally anything you want

## Credits

DefCon42, drew79, Brit
