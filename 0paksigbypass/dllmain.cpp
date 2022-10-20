// dllmain.cpp : Defines the entry point for the DLL application.
#include <pe/module.h>
#include <xorstr/include/xorstr.hpp>
#include <pluginsdk.h>
#include <searchers.h>

bool __cdecl init([[maybe_unused]] const Version client_version)
{
    NtCurrentPeb()->BeingDebugged = FALSE;
    if (const auto module = pe::get_module()) {
        uintptr_t handle = module->handle();
        const auto sections = module->segments();
        const auto& s1 = std::find_if(sections.begin(), sections.end(), [](const IMAGE_SECTION_HEADER& x) {
            return x.Characteristics & IMAGE_SCN_CNT_CODE;
            });
        const auto data = s1->as_bytes();

        // Look for FPakPlatformFile::BroadcastPakChunkSignatureCheckFailure(FPakChunkSignatureCheckFailedData*)
        auto result = std::search(data.begin(), data.end(), pattern_searcher(xorstr_("40 32 ED 41 FF 46 3C 41 8B 46 3C 41 8B 4E 30 83 E9 01 48 63 F9")));
        if (result != data.end()) {
            uintptr_t sigFailureAddr = (uintptr_t)&result[0] - 0x3C;

            DWORD oldprotect;
            BYTE retCode[] = { 0xC3, 0x90 };
            VirtualProtect((LPVOID)sigFailureAddr, sizeof(retCode), PAGE_EXECUTE_READWRITE, &oldprotect);
            memcpy((LPVOID)sigFailureAddr, (LPVOID)retCode, sizeof(retCode));
            VirtualProtect((LPVOID)sigFailureAddr, sizeof(retCode), oldprotect, &oldprotect);
        }
    }
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) PluginInfo GPluginInfo = {
  .hide_from_peb = true,
  .erase_pe_header = true,
  .init = init,
  .priority = 1,
  .target_apps = L"BNSR.exe"
};
