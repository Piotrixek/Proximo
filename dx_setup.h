#pragma once

#include <d3d11.h>
#include <Windows.h> 

bool InitializeDirect3D(HWND windowHandle);
void ShutdownDirect3D();
void BuildRenderTarget();
void DestroyRenderTarget();

ID3D11Device* GetDirect3DDevice();
ID3D11DeviceContext* GetDirect3DDeviceContext();
IDXGISwapChain* GetDirectXSwapChain();
ID3D11RenderTargetView* GetMainRenderTarget();