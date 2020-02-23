## Splendid Implanter

BattlEye .dll injector, done completely from user-mode.

## Details

This exploits a flaw in the user-mode component of BattlEye that should've never even existed to begin with.

By hooking CreateFileW, and checking if the lpFileName parameter contains our .dll's name then manipulating it to believe that Kernel32.dll is being loaded, we pass their dll checks and land our module inside of it as if it's a legitimate module.

The name is a play on Perfect Injector, don't mind that :).

## Features

support for:

- seh, c++ exceptions
- raw detouring without any tricks
- doing literally anything you want

## Credits

DefCon42, drew79, Brit
