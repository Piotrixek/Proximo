#include "dx_setup.h"
#include <comdef.h>
#include <tchar.h>

static ID3D11Device* globalDirect3DDevice = nullptr;
static ID3D11DeviceContext* globalDirect3DContext = nullptr;
static IDXGISwapChain* globalSwapChain = nullptr;
static ID3D11RenderTargetView* globalRenderTargetView = nullptr;

bool InitializeDirect3D(HWND windowHandle)
{
    DXGI_SWAP_CHAIN_DESC swapChainDescription;
    ZeroMemory(&swapChainDescription, sizeof(swapChainDescription));
    swapChainDescription.BufferCount = 2;
    swapChainDescription.BufferDesc.Width = 0;
    swapChainDescription.BufferDesc.Height = 0;
    swapChainDescription.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swapChainDescription.BufferDesc.RefreshRate.Numerator = 60;
    swapChainDescription.BufferDesc.RefreshRate.Denominator = 1;
    swapChainDescription.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    swapChainDescription.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swapChainDescription.OutputWindow = windowHandle;
    swapChainDescription.SampleDesc.Count = 1;
    swapChainDescription.SampleDesc.Quality = 0;
    swapChainDescription.Windowed = TRUE;
    swapChainDescription.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT deviceCreationFlags = 0;
    D3D_FEATURE_LEVEL activeFeatureLevel;
    const D3D_FEATURE_LEVEL supportedFeatureLevels[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };

    HRESULT resultCode = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, deviceCreationFlags, supportedFeatureLevels, 2, D3D11_SDK_VERSION, &swapChainDescription, &globalSwapChain, &globalDirect3DDevice, &activeFeatureLevel, &globalDirect3DContext);
    if (FAILED(resultCode)) {
        _com_error errorInformation(resultCode);
        MessageBox(windowHandle, errorInformation.ErrorMessage(), _T("D3D11CreateDeviceAndSwapChain Failed"), MB_OK | MB_ICONERROR);
        ShutdownDirect3D();
        return false;
    }

    BuildRenderTarget();
    if (!globalRenderTargetView) {
        ShutdownDirect3D();
        return false;
    }

    return true;
}

void ShutdownDirect3D()
{
    DestroyRenderTarget();
    if (globalSwapChain) { globalSwapChain->Release(); globalSwapChain = nullptr; }
    if (globalDirect3DContext) { globalDirect3DContext->Release(); globalDirect3DContext = nullptr; }
    if (globalDirect3DDevice) { globalDirect3DDevice->Release(); globalDirect3DDevice = nullptr; }
}

void BuildRenderTarget()
{
    if (!globalSwapChain || !globalDirect3DDevice) return;

    if (globalRenderTargetView) { globalRenderTargetView->Release(); globalRenderTargetView = nullptr; }

    ID3D11Texture2D* backBufferTexture = nullptr;
    HRESULT resultCode = globalSwapChain->GetBuffer(0, IID_PPV_ARGS(&backBufferTexture));
    if (SUCCEEDED(resultCode) && backBufferTexture) {
        resultCode = globalDirect3DDevice->CreateRenderTargetView(backBufferTexture, NULL, &globalRenderTargetView);
        backBufferTexture->Release();
        if (FAILED(resultCode)) {
            _com_error errorInformation(resultCode);
            MessageBox(NULL, errorInformation.ErrorMessage(), _T("CreateRenderTargetView Failed"), MB_OK | MB_ICONERROR);
            globalRenderTargetView = nullptr;
        }
    }
    else {
        _com_error errorInformation(resultCode);
        MessageBox(NULL, errorInformation.ErrorMessage(), _T("GetBuffer Failed"), MB_OK | MB_ICONERROR);
        globalRenderTargetView = nullptr;
    }
}

void DestroyRenderTarget()
{
    if (globalRenderTargetView) { globalRenderTargetView->Release(); globalRenderTargetView = nullptr; }
}

ID3D11Device* GetDirect3DDevice() { return globalDirect3DDevice; }
ID3D11DeviceContext* GetDirect3DDeviceContext() { return globalDirect3DContext; }
IDXGISwapChain* GetDirectXSwapChain() { return globalSwapChain; }
ID3D11RenderTargetView* GetMainRenderTarget() { return globalRenderTargetView; }