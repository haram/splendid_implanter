#pragma once
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <filesystem>
#include <memory>
#include <stdint.h>
#include <string_view>

#define FIND_NT_HEADER(x) reinterpret_cast<PIMAGE_NT_HEADERS>( uint64_t(x) + reinterpret_cast<PIMAGE_DOS_HEADER>(x)->e_lfanew )

#define LOG_LAST_ERROR() printf( "[!] failed at line %d, in file %s, last error: 0x%lx\n", __LINE__, __FILE__, GetLastError( ) )

#define RET_CHK(x)\
if (!x)\
{\
LOG_LAST_ERROR();\
return -1;\
}\

namespace impl
{
	using uq_handle = std::unique_ptr<void, decltype( &CloseHandle )>;

	__forceinline uint32_t get_process_id( const std::wstring_view process_name )
	{
		// open a system snapshot of all loaded processes
		uq_handle snap_shot{ CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ), &CloseHandle };

		if ( snap_shot.get( ) == INVALID_HANDLE_VALUE )
		{
			LOG_LAST_ERROR( );
			return 0;
		}

		PROCESSENTRY32W process_entry{ sizeof( PROCESSENTRY32W ) };

		// enumerate through processes
		for ( Process32FirstW( snap_shot.get( ), &process_entry ); Process32NextW( snap_shot.get( ), &process_entry ); )
			if ( std::wcscmp( process_name.data( ), process_entry.szExeFile ) == 0 )
				return process_entry.th32ProcessID;

		return 0;
	}

	__forceinline std::pair<void*, std::wstring> get_module_data( HANDLE process_handle, const std::wstring_view module_name )
	{
		auto loaded_modules = std::make_unique<HMODULE[ ]>( 64 );
		auto loaded_module_sz = 0;

		// enumerate all modules by handle, using size of 512 since the required size is in bytes, and an HMODULE is 8 bytes large.
		if ( !EnumProcessModules( process_handle, loaded_modules.get( ), 512, reinterpret_cast< PDWORD >( &loaded_module_sz ) ) )
		{
			LOG_LAST_ERROR( );
			return {};
		}

		for ( auto i = 0; i < loaded_module_sz / 8; i++ )
		{
			wchar_t file_name[ MAX_PATH ] = L"";

			// get the full working path for the current module
			if ( !GetModuleFileNameExW( process_handle, loaded_modules.get( )[ i ], file_name, _countof( file_name ) ) )
				continue;

			// module name returned will be a full path, check only for file name sub string.
			if ( std::wcsstr( file_name, module_name.data( ) ) != nullptr )
				return { loaded_modules.get( )[ i ], file_name };
		}

		return {};
	}

	__forceinline std::vector<uint8_t> get_file_data( const HANDLE file_handle, const std::wstring_view file_path )
	{
		const auto file_size = std::filesystem::file_size( file_path );

		std::vector<uint8_t> file_bytes{};
		file_bytes.resize( file_size );

		DWORD bytes_read = 0;
		if ( !ReadFile( file_handle, file_bytes.data( ), static_cast< DWORD >( file_size ), &bytes_read, nullptr ) )
		{
			LOG_LAST_ERROR( );
			return {};
		}

		printf( "[~] read %ikb from BEService [0x%p]\n", bytes_read / 1024, file_bytes.data( ) );

		return file_bytes;
	}

	__forceinline bool enable_privilege( const std::wstring_view privilege_name )
	{
		HANDLE token_handle = nullptr;

		if ( !OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle ) )
		{
			LOG_LAST_ERROR( );
			return false;
		}

		LUID luid{};
		if ( !LookupPrivilegeValueW( nullptr, privilege_name.data( ), &luid ) )
		{
			LOG_LAST_ERROR( );
			return false;
		}

		TOKEN_PRIVILEGES token_state{};
		token_state.PrivilegeCount = 1;
		token_state.Privileges[ 0 ].Luid = luid;
		token_state.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

		if ( !AdjustTokenPrivileges( token_handle, FALSE, &token_state, sizeof( TOKEN_PRIVILEGES ), nullptr, nullptr ) )
		{
			LOG_LAST_ERROR( );
			return false;
		}

		CloseHandle( token_handle );

		return true;
	}
}