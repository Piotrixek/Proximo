#include "menu.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "icons.h"
#include "ultralight_controller.h"
#include <memory>
#include <Windows.h>

extern std::unique_ptr<UltralightController> g_ultralight_controller;

int ConvertImGuiKeyToVirtualKey(ImGuiKey imguiKey)
{
	switch (imguiKey)
	{
	case ImGuiKey_Tab: return VK_TAB;
	case ImGuiKey_LeftArrow: return VK_LEFT;
	case ImGuiKey_RightArrow: return VK_RIGHT;
	case ImGuiKey_UpArrow: return VK_UP;
	case ImGuiKey_DownArrow: return VK_DOWN;
	case ImGuiKey_PageUp: return VK_PRIOR;
	case ImGuiKey_PageDown: return VK_NEXT;
	case ImGuiKey_Home: return VK_HOME;
	case ImGuiKey_End: return VK_END;
	case ImGuiKey_Insert: return VK_INSERT;
	case ImGuiKey_Delete: return VK_DELETE;
	case ImGuiKey_Backspace: return VK_BACK;
	case ImGuiKey_Space: return VK_SPACE;
	case ImGuiKey_Enter: return VK_RETURN;
	case ImGuiKey_Escape: return VK_ESCAPE;
	case ImGuiKey_A: return 'A'; case ImGuiKey_B: return 'B'; case ImGuiKey_C: return 'C';
	case ImGuiKey_D: return 'D'; case ImGuiKey_E: return 'E'; case ImGuiKey_F: return 'F';
	case ImGuiKey_G: return 'G'; case ImGuiKey_H: return 'H'; case ImGuiKey_I: return 'I';
	case ImGuiKey_J: return 'J'; case ImGuiKey_K: return 'K'; case ImGuiKey_L: return 'L';
	case ImGuiKey_M: return 'M'; case ImGuiKey_N: return 'N'; case ImGuiKey_O: return 'O';
	case ImGuiKey_P: return 'P'; case ImGuiKey_Q: return 'Q'; case ImGuiKey_R: return 'R';
	case ImGuiKey_S: return 'S'; case ImGuiKey_T: return 'T'; case ImGuiKey_U: return 'U';
	case ImGuiKey_V: return 'V'; case ImGuiKey_W: return 'W'; case ImGuiKey_X: return 'X';
	case ImGuiKey_Y: return 'Y'; case ImGuiKey_Z: return 'Z';
	case ImGuiKey_0: return '0'; case ImGuiKey_1: return '1'; case ImGuiKey_2: return '2';
	case ImGuiKey_3: return '3'; case ImGuiKey_4: return '4'; case ImGuiKey_5: return '5';
	case ImGuiKey_6: return '6'; case ImGuiKey_7: return '7'; case ImGuiKey_8: return '8';
	case ImGuiKey_9: return '9';
	case ImGuiKey_F1: return VK_F1; case ImGuiKey_F2: return VK_F2; case ImGuiKey_F3: return VK_F3;
	case ImGuiKey_F4: return VK_F4; case ImGuiKey_F5: return VK_F5; case ImGuiKey_F6: return VK_F6;
	case ImGuiKey_F7: return VK_F7; case ImGuiKey_F8: return VK_F8; case ImGuiKey_F9: return VK_F9;
	case ImGuiKey_F10: return VK_F10; case ImGuiKey_F11: return VK_F11; case ImGuiKey_F12: return VK_F12;
	default: return 0;
	}
}

int GetActiveKeyboardModifiers()
{
	auto& ioSettings = ImGui::GetIO();
	int activeModifiers = 0;
	if (ioSettings.KeyAlt) activeModifiers |= ultralight::KeyEvent::kMod_AltKey;
	if (ioSettings.KeyCtrl) activeModifiers |= ultralight::KeyEvent::kMod_CtrlKey;
	if (ioSettings.KeyShift) activeModifiers |= ultralight::KeyEvent::kMod_ShiftKey;
	if (ioSettings.KeySuper) activeModifiers |= ultralight::KeyEvent::kMod_MetaKey;
	return activeModifiers;
}

void DisplayMainInterface(bool* isWindowOpen)
{
	const ImGuiViewport* mainViewport = ImGui::GetMainViewport();
	ImGui::SetNextWindowPos(mainViewport->WorkPos);
	ImGui::SetNextWindowSize(mainViewport->WorkSize);
	ImGui::SetNextWindowViewport(mainViewport->ID);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

	ImGuiWindowFlags dockingWindowFlags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
		ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
		ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
		ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBackground;

	ImGui::Begin("DockspaceHost", NULL, dockingWindowFlags);
	ImGui::PopStyleVar(3);

	ImGuiID mainDockspaceIdentifier = ImGui::GetID("MyDockSpace");
	ImGui::DockSpace(mainDockspaceIdentifier, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_PassthruCentralNode);
	ImGui::End();

	ImGui::SetNextWindowSize(ImVec2(1200, 700), ImGuiCond_Once);

	ImGui::PushStyleColor(ImGuiCol_ResizeGrip, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
	ImGui::PushStyleColor(ImGuiCol_ResizeGripHovered, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));

	ImGui::Begin("Cowboy", isWindowOpen, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

	ImVec2 contentPosition = ImGui::GetCursorScreenPos();
	ImVec2 contentDimensions = ImGui::GetContentRegionAvail();
	if (contentDimensions.x < 1) contentDimensions.x = 1;
	if (contentDimensions.y < 1) contentDimensions.y = 1;

	if (g_ultralight_controller)
	{
		g_ultralight_controller->Resize((int)contentDimensions.x, (int)contentDimensions.y);

		g_ultralight_controller->Update();
		g_ultralight_controller->Render();

		ID3D11ShaderResourceView* renderedTexture = g_ultralight_controller->getTextureView();
		if (renderedTexture)
		{
			ImGui::GetWindowDrawList()->AddImage(
				(ImTextureID)reinterpret_cast<uintptr_t>(renderedTexture),
				contentPosition,
				ImVec2(contentPosition.x + contentDimensions.x, contentPosition.y + contentDimensions.y)
			);
		}
	}

	if (g_ultralight_controller && g_ultralight_controller->IsLoaded() && ImGui::IsWindowFocused())
	{
		ultralight::View* browserView = g_ultralight_controller->GetView();
		if (browserView) {
			ImGuiIO& activeInputIO = ImGui::GetIO();
			ImRect contentRectangleBounds(contentPosition, ImVec2(contentPosition.x + contentDimensions.x, contentPosition.y + contentDimensions.y));

			if (ImGui::IsMouseHoveringRect(contentRectangleBounds.Min, contentRectangleBounds.Max))
			{
				ultralight::MouseEvent mouseEvent;
				mouseEvent.x = (int)(activeInputIO.MousePos.x - contentPosition.x);
				mouseEvent.y = (int)(activeInputIO.MousePos.y - contentPosition.y);

				if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
				{
					mouseEvent.type = ultralight::MouseEvent::kType_MouseDown;
					mouseEvent.button = ultralight::MouseEvent::kButton_Left;
					browserView->FireMouseEvent(mouseEvent);
				}
				else if (ImGui::IsMouseReleased(ImGuiMouseButton_Left))
				{
					mouseEvent.type = ultralight::MouseEvent::kType_MouseUp;
					mouseEvent.button = ultralight::MouseEvent::kButton_Left;
					browserView->FireMouseEvent(mouseEvent);
				}
				else
				{
					mouseEvent.type = ultralight::MouseEvent::kType_MouseMoved;
					browserView->FireMouseEvent(mouseEvent);
				}

				if (activeInputIO.MouseWheel != 0.0f || activeInputIO.MouseWheelH != 0.0f)
				{
					ultralight::ScrollEvent scrollEvent;
					scrollEvent.type = ultralight::ScrollEvent::kType_ScrollByPixel;
					scrollEvent.delta_y = (int)(activeInputIO.MouseWheel * 100);
					scrollEvent.delta_x = (int)(activeInputIO.MouseWheelH * 100);
					browserView->FireScrollEvent(scrollEvent);
				}
			}

			int activeKeyboardModifiers = GetActiveKeyboardModifiers();
			for (int index = ImGuiKey_NamedKey_BEGIN; index < ImGuiKey_NamedKey_END; ++index)
			{
				ImGuiKey currentImGuiKey = static_cast<ImGuiKey>(index);
				int virtualKeyCode = ConvertImGuiKeyToVirtualKey(currentImGuiKey);
				if (virtualKeyCode == 0) continue;

				ultralight::KeyEvent keyboardEvent;
				keyboardEvent.virtual_key_code = virtualKeyCode;
				keyboardEvent.native_key_code = virtualKeyCode;
				keyboardEvent.modifiers = activeKeyboardModifiers;

				if (ImGui::IsKeyPressed(currentImGuiKey, false))
				{
					keyboardEvent.type = ultralight::KeyEvent::kType_RawKeyDown;
					browserView->FireKeyEvent(keyboardEvent);
				}
				if (ImGui::IsKeyReleased(currentImGuiKey))
				{
					keyboardEvent.type = ultralight::KeyEvent::kType_KeyUp;
					browserView->FireKeyEvent(keyboardEvent);
				}
			}

			if (!activeInputIO.InputQueueCharacters.empty())
			{
				for (int index = 0; index < activeInputIO.InputQueueCharacters.Size; index++)
				{
					ImWchar currentCharacter = activeInputIO.InputQueueCharacters[index];
					if (currentCharacter == 0 || currentCharacter >= 0xF700) continue;
					ultralight::KeyEvent characterEvent;
					characterEvent.type = ultralight::KeyEvent::kType_Char;
					characterEvent.text = ultralight::String16((ultralight::Char16*)&currentCharacter, 1);
					browserView->FireKeyEvent(characterEvent);
				}
			}
		}
	}

	ImGui::End();
	ImGui::PopStyleColor(2);
}