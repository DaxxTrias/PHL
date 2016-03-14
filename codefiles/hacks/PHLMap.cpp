#include "PHLMap.h"
#include "../PHLConsole.h"

#define MAP_HACK_OFFSET_1 0x01;
#define MAP_HACK_OFFSET_2 0x10;
#define MAP_HACK_OFFSET_3 0x1C;
#define MAP_HACK_OFFSET_4 0x28;

#define MAP_HACK_PATCH_VALUE 0xE8;

PHLMap::PHLMap ()
{
	/*
		Search:
			\xD9\x00\x8B\x0C\x24

		Patch:
			0x01 = 0xE8
			0x10 = 0xE8
			0x1C = 0xE8
			0x28 = 0xE8
	*/
	mapHackOff =
		PHLMemory::findPattern(HexPattern(
			"8B 10 89 16 8B 74 24 08 83 C6 04 89 74 24 "
			"08 8B 10 89 16 8B 74 24 08 83 C6 04 89 74 24 08 8B 10 89 16"));

	CodeCave cc (mapHackOff, { 0xE8 });

	cc.addr = mapHackOff + MAP_HACK_OFFSET_1;
	cc.createCodeCave ();
	cc.addr = mapHackOff + MAP_HACK_OFFSET_2;
	cc.createCodeCave ();
	cc.addr = mapHackOff + MAP_HACK_OFFSET_3;
	cc.createCodeCave ();
	cc.addr = mapHackOff + MAP_HACK_OFFSET_4;
	cc.createCodeCave ();
}

void PHLMap::printAddr ()
{
	Addr base = PHLMemory::Instance ()->base;
	PHLConsole::printLog ("Map Hack Offset:        %.8X, PathOfExile + %.8X\n",
						  mapHackOff, mapHackOff - base);
}
