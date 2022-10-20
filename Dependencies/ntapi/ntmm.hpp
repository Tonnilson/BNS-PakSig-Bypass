#pragma once
#include <phnt_windows.h>
#include <phnt.h>

#include <intrin.h>
#pragma intrinsic(_BitScanForward)

#include <type_traits>

#include <wil/result.h>
#include <wil/resource.h>
#include <wil/win32_helpers.h>

namespace nt::mm
{
  constexpr ULONG page_execute_any = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
  constexpr ULONG page_write_any = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOMBINE;
  constexpr ULONG page_writecopy_any = PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;

  inline PVOID page_align(PVOID Va, ULONG PageSize)
  {
    return reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(Va) & ~(static_cast<SIZE_T>(PageSize) - 1));
  }

  inline SIZE_T address_and_size_to_span_pages(PVOID Va, SIZE_T Size, ULONG PageSize)
  {
    ULONG PageShift;
    if ( !Size || !_BitScanForward(&PageShift, PageSize) ) return 0;

    return (((Size - 1) >> PageShift) +
            ((((static_cast<ULONG>(Size - 1) & (PageSize - 1)) + (static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(Va)) & (PageSize - 1)))) >> PageShift)) + 1L;
  }

  class protect_memory
  {
  private:
    HANDLE ProcessHandle;
    PVOID BaseAddress;
    SIZE_T RegionSize;
    ULONG OldProtect;

  public:
    protect_memory() = delete;
    protect_memory(protect_memory &) = delete;

    protect_memory(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T RegionSize, ULONG NewProtect)
      : ProcessHandle(ProcessHandle)
    {
      SYSTEM_BASIC_INFORMATION sbi;
      THROW_IF_NTSTATUS_FAILED(NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(SYSTEM_BASIC_INFORMATION), nullptr));

      this->BaseAddress = page_align(BaseAddress, sbi.PageSize);
      this->RegionSize = sbi.PageSize * address_and_size_to_span_pages(BaseAddress, RegionSize, sbi.PageSize);
      THROW_IF_NTSTATUS_FAILED(NtProtectVirtualMemory(ProcessHandle, &this->BaseAddress, &this->RegionSize, NewProtect, &this->OldProtect));
    }

    protect_memory(PVOID BaseAddress, SIZE_T RegionSize, ULONG NewProtect)
      : protect_memory(NtCurrentProcess(), BaseAddress, RegionSize, NewProtect)
    {
    }

    ~protect_memory()
    {
      THROW_IF_NTSTATUS_FAILED(NtProtectVirtualMemory(ProcessHandle, &this->BaseAddress, &this->RegionSize, this->OldProtect, &this->OldProtect));
    }
  };
}
