#pragma once
#include "misc_utils.hpp"
#include "win_utils.hpp"

EXTERN_C int LDE( void*, int );

namespace be_bypass
{
	namespace detail
	{
		inline impl::uq_handle process_handle = { nullptr, nullptr };
		inline impl::uq_handle file_handle = { nullptr, nullptr };

		inline void* image_base = nullptr;
		inline std::wstring image_path = {};

		inline std::pair<uint32_t, uint32_t> target_section = { 0, 0 };
		inline std::vector<uint8_t> stub_data = {};

		inline uint8_t* our_dll_buffer = nullptr;
		inline uint8_t* kernel32_dll_buffer = nullptr;
	}

	bool initialize( )
	{
		printf( "[~] entering %s\n", __FUNCTION__ );

		printf( "[~] waiting for BEService...\n" );

		const auto be_process_id = impl::wait_on_object( [ ]( ) { return impl::get_process_id( L"BEService.exe" ); } );

		if ( !be_process_id )
		{
			printf( "[!] timed out" );
			return false;
		}

		printf( "[~] found BEService process [%d]\n", be_process_id );

		// open handle to beservice
		detail::process_handle = { OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, be_process_id ), &CloseHandle };

		// return value is NULL incase of failure
		if ( !detail::process_handle )
		{
			LOG_LAST_ERROR( );
			return false;
		}

		printf( "[~] opened BEService process handle [0x%p]\n", detail::process_handle.get( ) );

		// retrieve module data
		const auto be_data = impl::get_module_data( detail::process_handle.get( ), L"BEService.exe" );

		// shouldn't be possible
		if ( !be_data.first )
		{
			printf( "[!] failed to find BEService data" );
			return false;
		}

		detail::image_base = be_data.first;
		detail::image_path = be_data.second;

		printf( "[~] retrieved BEService address [0x%p]\n", detail::image_base );

		// get handle to file on disk
		detail::file_handle = { CreateFileW( detail::image_path.c_str( ), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, INVALID_HANDLE_VALUE ), &CloseHandle };

		// return value is INVALID_HANDLE_VALUE incase of failure
		if ( detail::file_handle.get( ) == INVALID_HANDLE_VALUE )
		{
			LOG_LAST_ERROR( );
			return false;
		}

		printf( "[~] opened BEService disk handle [0x%p]\n", detail::file_handle.get( ) );

		auto be_disk_buffer = impl::get_file_data( detail::file_handle.get( ), detail::image_path );

		// look for an executable section to deploy hook in
		const auto buffer_start = be_disk_buffer.data( );

		// get the NT header
		const auto nt_header = FIND_NT_HEADER( buffer_start );

		// search for an executable section
		const auto section_header = IMAGE_FIRST_SECTION( nt_header );
		const auto section_header_end = section_header + nt_header->FileHeader.NumberOfSections;

		// get section that has IMAGE_SCN_MEM_EXECUTE flag, and no raw data.
		auto executable_section = std::find_if( section_header, section_header_end, [ ]( const auto& section ) { return section.SizeOfRawData != 0 && ( section.Characteristics & IMAGE_SCN_MEM_EXECUTE ) == IMAGE_SCN_MEM_EXECUTE; } );

		if ( executable_section == section_header_end )
		{
			printf( "[!] can't find needed section" );
			return false;
		}

		const auto target_section = executable_section;

		printf( "[~] found target section [%s]\n", reinterpret_cast< const char* >( target_section->Name + 1 ) );

		detail::target_section = { target_section->VirtualAddress, target_section->Misc.VirtualSize };

		printf( "[~] leaving %s\n", __FUNCTION__ );

		return true;
	}

	bool prepare_image( const wchar_t* image_short_name )
	{
		printf( "[~] entering %s\n", __FUNCTION__ );

		// since w10 1607, the limit for maximum path isn't actually MAX_PATH, just assume it is.
		auto dll_path = std::make_unique<wchar_t[ ]>( MAX_PATH );
		GetFullPathNameW( image_short_name, MAX_PATH, dll_path.get( ), nullptr );

		printf( "[~] dll path: %ws\n", dll_path.get( ) );

		const auto dll_path_sz = wcslen( dll_path.get( ) ) * 2;

		auto kernel_path = std::make_unique<wchar_t[ ]>( MAX_PATH );
		GetModuleFileNameW( GetModuleHandleW( L"Kernel32.dll" ), kernel_path.get( ), MAX_PATH );

		printf( "[~] kernel32 path: %ws\n", kernel_path.get( ) );

		const auto kernel_path_sz = wcslen( kernel_path.get( ) ) * 2;

		// allocate a buffer in the process to hold our paths
		const auto paths_buffer = VirtualAllocEx( detail::process_handle.get( ), nullptr, dll_path_sz + kernel_path_sz + 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

		if ( !paths_buffer )
		{
			LOG_LAST_ERROR( );
			return false;
		}

		printf( "[~] allocated buffer at 0x%p\n", paths_buffer );

		RET_CHK( WriteProcessMemory( detail::process_handle.get( ), paths_buffer, dll_path.get( ), dll_path_sz, nullptr ) )

		detail::our_dll_buffer = reinterpret_cast< uint8_t* >( paths_buffer );
		printf( "[~] wrote dll path successfully!\n" );

		const auto second_path_buffer = reinterpret_cast< uint8_t* >( paths_buffer ) + dll_path_sz + 2;

		RET_CHK( WriteProcessMemory( detail::process_handle.get( ), second_path_buffer, kernel_path.get( ), kernel_path_sz, nullptr ) )

		detail::kernel32_dll_buffer = second_path_buffer;
		printf( "[~] wrote kernel32 path successfully!\n" );

		printf( "[~] leaving %s\n", __FUNCTION__ );

		return true;
	}

	bool deploy_image( )
	{
		printf( "[~] entering %s\n", __FUNCTION__ );

		uint8_t jmp_stub[ ]
		{
			0x51, 0x48, 0xb9, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			0xcc, 0xcc, 0x48, 0x87, 0x0c, 0x24, 0xc3
		};

		// DefCon42 is sexy
		uint8_t shell_code[ ]
		{
			0x41, 0x54, 0x41, 0x55, 0x49, 0x89, 0xca, 0x49, 0xbc,
			0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x4d,
			0x0f, 0xb7, 0x2c, 0x24, 0x4d, 0x85, 0xed, 0x74, 0x1e,
			0x4d, 0x0f, 0xb7, 0x1a, 0x4d, 0x85, 0xdb, 0x74, 0x1f,
			0x4d, 0x39, 0xeb, 0x75, 0x0a, 0x49, 0x83, 0xc2, 0x02,
			0x49, 0x83, 0xc4, 0x02, 0xeb, 0xde, 0x49, 0x83, 0xc2,
			0x02, 0xeb, 0xce, 0x48, 0xb9, 0xcc, 0xcc, 0xcc, 0xcc,
			0xcc, 0xcc, 0xcc, 0xcc, 0x41, 0x5d, 0x41, 0x5c
		};

		const auto kernel_base = GetModuleHandleW( L"Kernelbase.dll" );

		if ( !kernel_base )
		{
			LOG_LAST_ERROR( );
			return false;
		}

		const auto export_address = reinterpret_cast< uint8_t* >( GetProcAddress( kernel_base, "CreateFileW" ) );

		if ( !export_address )
		{
			LOG_LAST_ERROR( );
			return false;
		}

		printf( "[~] found CreateFileW [0x%p]\n", export_address );

		printf( "[~] preparing stub...\n" );

		// calculate buffer length based on bytes needed from original
		auto og_len = 0;

		while ( og_len < sizeof( jmp_stub ) )
			og_len += LDE( export_address + og_len, 64 );

		const auto buf_len = og_len + sizeof( shell_code ) + sizeof( jmp_stub );
		detail::stub_data.resize( buf_len );

		const auto og_data = export_address + og_len;

		const auto stub_data_start = detail::stub_data.data( );

		// :)
		memcpy( stub_data_start, shell_code, sizeof( shell_code ) );
		memcpy( stub_data_start + 0x9, &detail::our_dll_buffer, 8 );
		memcpy( stub_data_start + 0x3b, &detail::kernel32_dll_buffer, 8 );
		memcpy( stub_data_start + sizeof( shell_code ), export_address, og_len );
		memcpy( stub_data_start + sizeof( shell_code ) + og_len, jmp_stub, sizeof( jmp_stub ) );
		memcpy( stub_data_start + sizeof( shell_code ) + og_len + 3, &og_data, 8 );

		printf( "[~] stub prepared\n" );

		const auto deployment_location = ( reinterpret_cast< uint8_t* >( detail::image_base ) + detail::target_section.first + detail::target_section.second ) - buf_len;

		printf( "[~] deploying stub...\n" );

		DWORD cache = 0;

		RET_CHK( VirtualProtectEx( detail::process_handle.get( ), deployment_location, buf_len, PAGE_EXECUTE_READWRITE, &cache ) )
		RET_CHK( WriteProcessMemory( detail::process_handle.get( ), deployment_location, stub_data_start, detail::stub_data.size( ), nullptr ) )
		RET_CHK( VirtualProtectEx( detail::process_handle.get( ), deployment_location, buf_len, cache, &cache ) )

		*reinterpret_cast< uint64_t* >( &jmp_stub[ 3 ] ) = reinterpret_cast< uint64_t >( deployment_location );

		RET_CHK( WriteProcessMemory( detail::process_handle.get( ), export_address, jmp_stub, sizeof( jmp_stub ), nullptr ) )

		printf( "[~] stub deployed!\n" );

		printf( "[~] leaving %s\n", __FUNCTION__ );

		return true;
	}

	bool inject_image( const wchar_t* window_class_name, const wchar_t* image_short_name )
	{
		printf( "[~] entering %s\n", __FUNCTION__ );

		printf( "[~] waiting for game to open...\n" );

		const auto game_window = impl::wait_on_object( [ window_class_name ]( ) { return FindWindowW( window_class_name, nullptr ); } );

		if ( !game_window )
		{
			printf( "[!] timed out\n" );
			return false;
		}

		const auto window_thread = GetWindowThreadProcessId( game_window, nullptr );

		if ( !window_thread )
		{
			LOG_LAST_ERROR( );
			return false;
		}

		printf( "[~] window thread found [0x%lx]\n", window_thread );

		// since w10 1607, the limit for maximum path isn't actually MAX_PATH, just assume it is.
		auto dll_path = std::make_unique<wchar_t[ ]>( MAX_PATH );
		GetFullPathNameW( image_short_name, MAX_PATH, dll_path.get( ), nullptr );

		const auto loaded_module = LoadLibraryW( dll_path.get( ) );

		if ( !loaded_module )
		{
			LOG_LAST_ERROR( );
			return false;
		}

		printf( "[~] loaded module to local process [0x%p]\n", loaded_module );

		const auto window_hook = GetProcAddress( loaded_module, "wnd_hk" );

		if ( !window_hook )
		{
			printf( "[!] can't find needed export in implanted dll, last error: 0x%lx", GetLastError( ) );
			return false;
		}

		const auto window_hook = SetWindowsHookExW( WH_GETMESSAGE, reinterpret_cast< HOOKPROC >( GetProcAddress( GetModuleHandleA( "Kernelbase.dll" ), "CreateFileW" ) ), loaded_module, window_thread );

		printf( "[~] posting message...\n" );

		// spam the fuck out of the message handler
		for ( auto i = 0; i < 50; i++ )
			PostThreadMessageW( window_thread, 0x5b0, 0, 0 );

		printf( "[~] dll implanted\n" );

		printf( "[~] leaving %s\n", __FUNCTION__ );

		return true;
	}
}