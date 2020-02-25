#pragma once
#include <thread>
#include <chrono>

namespace impl
{
	template <typename T, class Fn>
	void wait_on_object( T* out_var, Fn function )
	{
		if ( !out_var )
			throw std::exception( "out_var was nullptr in wait_on_object" );

		*out_var = T( );

		const auto cached_time = std::chrono::system_clock::now( );

		while ( !*out_var )
		{
			const auto current_time_mins = std::chrono::duration_cast< std::chrono::minutes >( std::chrono::system_clock::now( ) - cached_time ).count( );

			if ( current_time_mins >= 2u )
				break;

			*out_var = function( );
			std::this_thread::sleep_for( std::chrono::milliseconds( 250 ) );
		}
	}
}