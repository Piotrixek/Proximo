#include "window_setup.h"
#include "dx_setup.h"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include <comdef.h>
#include <memory>
#include <tchar.h>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND windowHandle, UINT windowMessage, WPARAM wordParameter, LPARAM longParameter);

HWND InitializeHostWindow(HINSTANCE applicationInstance, const TCHAR* windowClassName)
{
    WNDCLASSEX windowClass = { sizeof(WNDCLASSEX), CS_CLASSDC, HandleWindowMessages, 0L, 0L, applicationInstance, NULL, NULL, NULL, NULL, windowClassName, NULL };
    if (!::RegisterClassEx(&windowClass)) {
        MessageBox(NULL, _T("Failed to register window class!"), _T("Error"), MB_OK | MB_ICONERROR);
        return NULL;
    }

    HWND createdWindowHandle = ::CreateWindowEx(
        0, windowClass.lpszClassName, _T("V-Launch Host"), WS_POPUP,
        0, 0, 1, 1,
        NULL, NULL, windowClass.hInstance, NULL);

    if (!createdWindowHandle) {
        MessageBox(NULL, _T("Failed to create hidden host window!"), _T("Error"), MB_OK | MB_ICONERROR);
        ::UnregisterClass(windowClass.lpszClassName, windowClass.hInstance);
        return NULL;
    }

    return createdWindowHandle;
}

void DestroyHostWindow(HINSTANCE applicationInstance, const TCHAR* windowClassName)
{
    ::UnregisterClass(windowClassName, applicationInstance);
}

LRESULT WINAPI HandleWindowMessages(HWND windowHandle, UINT windowMessage, WPARAM wordParameter, LPARAM longParameter)
{
    if (ImGui::GetCurrentContext() && ImGui_ImplWin32_WndProcHandler(windowHandle, windowMessage, wordParameter, longParameter))
        return true;

    switch (windowMessage)
    {
    case WM_SIZE:
    {
        IDXGISwapChain* activeSwapChain = GetDirectXSwapChain();
        if (activeSwapChain != NULL && wordParameter != SIZE_MINIMIZED)
        {
            DestroyRenderTarget();
            HRESULT resultCode = activeSwapChain->ResizeBuffers(0, (UINT)LOWORD(longParameter), (UINT)HIWORD(longParameter), DXGI_FORMAT_UNKNOWN, 0);
            if (SUCCEEDED(resultCode)) {
                BuildRenderTarget();
            }
            else {
                _com_error errorInformation(resultCode);
                MessageBox(windowHandle, errorInformation.ErrorMessage(), _T("ResizeBuffers Failed"), MB_OK | MB_ICONERROR);
            }
        }
        return 0;
    }
    case WM_SYSCOMMAND:
        if ((wordParameter & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }

    return ::DefWindowProc(windowHandle, windowMessage, wordParameter, longParameter);
}