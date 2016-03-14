#include "PHLBypass.h"
#include "../PHLConsole.h"

PHLBypass * PHLBypass::phlBypass = nullptr;

PHLBypass::PHLBypass ()
{
	setBypassOffsetA ();
	setBypassOffsetB ();
	setBypassOffsetC ();

	activateBypassA ();
	activateBypassB ();
	activateBypassC ();
}

bool PHLBypass::setBypassOffsetA ()
{
	/*
	// post 2.1.2d
	search: 32 C0 C3 E8 ?? ?? ?? ?? 6A 00
	*/
	HexPattern hexPattern("32 C0 C3 E8 ?? ?? ?? ?? 6A 00 ");

	bypassA = PHLMemory::findPattern(hexPattern);
	bypassA -= 0x02;

	if (!isAddressValid (bypassA))
	{
		return false;
	}
	return true;
}

bool PHLBypass::setBypassOffsetB ()
{
	/*
		// post 2.1.2d
		search: 6A 04 68 ?? ?? ?? ?? 8D 44
				24 10 C7 44 24 ?? ?? ?? ?? ??
	*/
	HexPattern hexPattern("6A 04 68 ?? ?? ?? ?? 8D 44 24 10 C7 44 24 ?? ?? ?? ?? ??");

	bypassB = PHLMemory::findPattern(hexPattern);

	bypassB -= 0x19;

	if (!isAddressValid (bypassB))
	{
		return false;
	}
	return true;
}

bool PHLBypass::setBypassOffsetC ()
{
	/*
		// pre 2.1.2d
		search: 55 8b ec 83
				e4 f8 83 ec
				08 ?? ?? ??
				?? ?? ?? ??
				53 55 56 57
				0F
		before: 0f 84 cd 00 00 00
		after:  e9 ce 00 00 00 90
	*/
	/*
		// post 2.1.2d
		search: 51 80 3D ?? ?? ?? ?? ?? 75 2E
	*/
	HexPattern hexPattern ("51 80 3D ?? ?? ?? ?? ?? 75 2E");

	bypassC = PHLMemory::findPattern (hexPattern);

	if (!isAddressValid (bypassC))
	{
		return false;
	}

	bypassC += 0x18;

	return true;
}

PHLBypass * PHLBypass::Instance ()
{
	if (!phlBypass)
	{
		phlBypass = new PHLBypass;
	}
	return phlBypass;
}

void PHLBypass::printAddr ()
{
	Addr base = PHLMemory::Instance ()->base;
	PHLConsole::printLog (
		"Bypass A:               %.8X, PathOfExile + %.8X\n"
		"Bypass B:               %.8X, PathOfExile + %.8X\n"
		"Bypass C:               %.8X, PathOfExile + %.8X\n",
		bypassA, bypassA - base,
		bypassB, bypassB - base,
		bypassC, bypassC - base);
}

bool PHLBypass::activateBypassA ()
{
	// Change jz 5 to nops so it returns
	CodeCave cc =
		CodeCave (bypassA,
		{ 0x90, 0x90 });
	if (cc.createCodeCave ())
	{
		return true;
	}
	return false;
}

bool PHLBypass::activateBypassB ()
{
	/*
		// pre 2.1.2d
		Change jnz to jmp so it always jumps
		25EA07

		To do this we change:
		0F 85 9E 00 00 00
		To:
		E9 9F 00 00 00 90

		It changes from 9E to 9F because we jump
		relatively in bytes, and since we add a nop
		after, we have to jump that extra nop byte
	*/
	/*
		// post 2.1.2d
		before: 0F 85 97 00 00 00
		after: E9 98 00 00 00 90
	*/

	Addr entry = bypassB;
	DWORD jumpDist = PHLMemory::readAddr (entry + 0x2) + 0x1;

	BYTE * bytes = (BYTE*)(&jumpDist);

	CodeCave cc = CodeCave (entry,
	{ 0xE9,
	bytes[0], bytes[1],
	bytes[2], bytes[3],
	0x90 });

	if (cc.createCodeCave ())
	{
		return true;
	}
	return false;
}

bool PHLBypass::activateBypassC ()
{
	/*
		// pre 2.1.2d
		before: 0f 84 cd 00 00 00
		after:  e9 ce 00 00 00 90
	*/
	/*
		// post 2.1.2d
		before: 74 10
		after: eb 10
	*/

	Addr entry = bypassC;
	DWORD jumpDist = PHLMemory::readAddr (entry + 0x2) + 0x1;

	BYTE * bytes = (BYTE*)(&jumpDist);

	CodeCave cc = CodeCave (entry,
	{ 0xEB, bytes[0] });

	if (cc.createCodeCave ())
	{
		return true;
	}
	return false;
}