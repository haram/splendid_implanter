#pragma once
#include <stdint.h>

template <typename T>
struct list_t
{
	T** contents;
	uint32_t size : 30;
	uint32_t capacity;
};

struct entity_events_t
{
	char pad_0[ 0xd8 ];
	list_t<void> components;
};

struct entity_t
{
	char pad_0[ 0x28 ];
	entity_events_t* event_listener;
};

struct game_manager_t
{
	char pad_0[ 0x1c8 ];
	list_t<entity_t> entity_list;
};

struct game_state_t
{
	char pad_0[ 0x2e8 ];
	uint8_t game_state;
};