#include <thread>
#include <chrono>

#include "mem_utils.hpp"
#include "game_structs.hpp"

bool is_in_game( game_state_t* state_manager )
{
	const auto game_state = state_manager->game_state;

	// == prep phase, == action phase
	return game_state == PREP_PHASE || game_state == ACTION_PHASE;
}

unsigned long main_thread( void* )
{
	// xref: PlayerMarkerComponent
	const auto player_marker_xref_sig = impl::find_signature( "RainbowSix.exe", "4c 89 0b 48 8d 15" ) + 3;

	if ( reinterpret_cast< uint64_t >( player_marker_xref_sig ) <= 3 )
	{
		MessageBoxA( nullptr, "player marker sig is invalid", "secret.club", MB_OK );
		return 0;
	}

	const auto player_marker_component = player_marker_xref_sig + *reinterpret_cast< int32_t* >( player_marker_xref_sig + 3 ) + 7;

	// xref: R6TrackingManager or attackingTeamIndex (first mov rax above)
	const auto game_manager_sig = impl::find_signature( "RainbowSix.exe", "48 8b 05 ? ? ? ? 8b 8e" );

	if ( !game_manager_sig )
	{
		MessageBoxA( nullptr, "game manager sig is invalid", "secret.club", MB_OK );
		return 0;
	}

	const auto game_manager = *reinterpret_cast< game_manager_t** >( game_manager_sig + *reinterpret_cast< int32_t* >( game_manager_sig + 3 ) + 7 );

	// search for immediate value 0x2e8, or any cmp [rcx+0x2e8], 2
	const auto state_manager_sig = impl::find_signature( "RainbowSix.exe", "48 8b 05 ? ? ? ? 8b 90 e8 02" );

	if ( !state_manager_sig )
	{
		MessageBoxA( nullptr, "state manager sig is invalid", "secret.club", MB_OK );
		return 0;
	}

	const auto state_manager = *reinterpret_cast< game_state_t** >( state_manager_sig + *reinterpret_cast< int32_t* >( state_manager_sig + 3 ) + 7 );

	while ( true )
	{
		static auto esp_enabled = true;

		if ( GetAsyncKeyState( VK_INSERT ) & 1 )
			esp_enabled = !esp_enabled;

		if ( !is_in_game( state_manager ) )
			continue;

		const auto entity_list = game_manager->entity_list;

		if ( !entity_list.contents )
			continue;

		for ( auto i = 0u; i < entity_list.size; i++ )
		{
			const auto entity = entity_list.contents[ i ];

			if ( !entity )
				continue;

			// check if player's a bot, bots are always in .data
			const auto higher_bits = static_cast< uint32_t >( reinterpret_cast< uint64_t >( entity ) >> 32 );

			if ( higher_bits == BOT_NORMAL || higher_bits == BOT_NORMAL2 )
				continue;

			const auto event_listener = entity->event_listener;

			if ( !event_listener )
				continue;

			const auto components = event_listener->components;

			if ( !components.contents )
				continue;

			for ( auto j = 0u; j < components.size; j++ )
			{
				const auto component = reinterpret_cast< uint8_t* >( components.contents[ j ] );

				if ( !component || *reinterpret_cast< uint8_t** >( component ) != player_marker_component )
					continue;

				*reinterpret_cast< bool* >( component + 0x534 ) = esp_enabled;
			}
		}

		std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) );
	}

	return 0;
}

bool DllMain( HMODULE module_instance, DWORD call_reason, void* )
{
	if ( call_reason != DLL_PROCESS_ATTACH )
		return false;

	wchar_t file_name[ MAX_PATH ] = L"";
	GetModuleFileNameW( module_instance, file_name, _countof( file_name ) );
	LoadLibraryW( file_name );

	return true;
}

extern "C" __declspec( dllexport )
LRESULT wnd_hk( int32_t code, WPARAM wparam, LPARAM lparam )
{
	// handle race condition from calling hook multiple times
	static auto done_once = false;

	const auto pmsg = reinterpret_cast< MSG* >( lparam );

	if ( !done_once && pmsg->message == 0x5b0 )
	{
		UnhookWindowsHookEx( reinterpret_cast< HHOOK >( lparam ) );

		// you can just one line this since CloseHandle doesn't throw unless it's under debug mode
		if ( const auto handle = CreateThread( nullptr, 0, &main_thread, nullptr, 0, nullptr ); handle != nullptr )
			CloseHandle( handle );

		done_once = true;
	}

	// call next hook in queue
	return CallNextHookEx( nullptr, code, wparam, lparam );
}