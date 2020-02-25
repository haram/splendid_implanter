#pragma once
#include <thread>
#include <chrono>

namespace impl
{
	using clock = std::chrono::steady_clock;

	template <class Fn>
	auto wait_on_object( Fn function, clock::duration interval = std::chrono::milliseconds( 250 ), clock::duration time_out = std::chrono::minutes( 2 ) ) -> decltype( function( ) )
	{
		const auto start_time = clock::now( );

		while ( clock::now( ) - start_time < time_out )
		{
			if ( const auto result = function( ); result )
				return result;

			std::this_thread::sleep_for( interval );
		}

		return {};
	}
}