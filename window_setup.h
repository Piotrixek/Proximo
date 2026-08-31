#pragma once

#include <Windows.h>
#include <tchar.h>

HWND InitializeHostWindow(HINSTANCE applicationInstance, const TCHAR* windowClassName);
void DestroyHostWindow(HINSTANCE applicationInstance, const TCHAR* windowClassName);
LRESULT WINAPI HandleWindowMessages(HWND windowHandle, UINT windowMessage, WPARAM wordParameter, LPARAM longParameter);