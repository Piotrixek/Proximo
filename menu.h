#pragma once

namespace ImGui
{
    bool ToggleButton(const char* elementIdentifier, bool* toggleState);
}

void DisplayMainInterface(bool* isWindowOpen);