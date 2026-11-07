// Console.h
// No-CRT console output for ForceIO.
// © WESMAR Marek Wesołowski

#pragma once

#include <windows.h>

void Con_Init(void);
void Con_Print(const wchar_t* msg);
void Con_Error(const wchar_t* msg);
void Con_Hex32(unsigned long val);
void Con_Dec(unsigned long val);
BOOL Con_ConfirmOverwrite(const wchar_t* path);
