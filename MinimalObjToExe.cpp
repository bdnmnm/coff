#include <windows.h>

#include <cstdint>
#include <ctime>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

size_t AlignUp(size_t value, size_t alignment) {
    return ((value + alignment - 1u) / alignment) * alignment;
}

void AppendBytes(std::vector<std::uint8_t>& dst, const void* src, size_t size) {
    const auto* p = static_cast<const std::uint8_t*>(src);
    dst.insert(dst.end(), p, p + size);
}

template <typename T>
void AppendStruct(std::vector<std::uint8_t>& dst, const T& value) {
    AppendBytes(dst, &value, sizeof(T));
}

void AppendZeros(std::vector<std::uint8_t>& dst, size_t count) {
    dst.insert(dst.end(), count, 0);
}

bool BuildMinimalObj(std::vector<std::uint8_t>& outObj, std::wstring& error) {
    IMAGE_FILE_HEADER fileHeader{};
    fileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    fileHeader.NumberOfSections = 1;
    fileHeader.TimeDateStamp = static_cast<DWORD>(std::time(nullptr));

    IMAGE_SECTION_HEADER section{};
    std::memcpy(section.Name, ".text", 5);
    section.Misc.VirtualSize = 1;
    section.SizeOfRawData = 1;
    section.PointerToRawData = sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_SECTION_HEADER);
    section.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    outObj.clear();
    AppendStruct(outObj, fileHeader);
    AppendStruct(outObj, section);

    const std::uint8_t retInstruction = 0xC3;
    AppendStruct(outObj, retInstruction);

    if (outObj.size() < sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_SECTION_HEADER) + 1) {
        error = L"Failed to build minimal OBJ in memory.";
        return false;
    }

    return true;
}

bool ValidateMinimalObj(const std::vector<std::uint8_t>& objBytes, std::wstring& error) {
    if (objBytes.size() < sizeof(IMAGE_FILE_HEADER)) {
        error = L"OBJ image is too small.";
        return false;
    }

    const IMAGE_FILE_HEADER* header = reinterpret_cast<const IMAGE_FILE_HEADER*>(objBytes.data());
    if (header->Machine != IMAGE_FILE_MACHINE_AMD64) {
        error = L"Only x64 (IMAGE_FILE_MACHINE_AMD64) OBJ is supported.";
        return false;
    }

    if (header->NumberOfSections == 0) {
        error = L"OBJ with zero sections cannot be converted.";
        return false;
    }

    return true;
}

bool BuildHelloWorldExe(const std::wstring& outputPath, std::wstring& error) {
    constexpr std::uint32_t kFileAlignment = 0x200;
    constexpr std::uint32_t kSectionAlignment = 0x1000;
    constexpr std::uint64_t kImageBase = 0x140000000ULL;
    constexpr std::uint32_t kTextRva = 0x1000;
    constexpr std::uint32_t kRdataRva = 0x2000;

    std::vector<std::uint8_t> text = {
        0x48, 0x83, 0xEC, 0x28, 0x48, 0x31, 0xC9, 0x48, 0x8D, 0x15, 0, 0, 0, 0,
        0x4C, 0x8D, 0x05, 0, 0, 0, 0, 0x45, 0x31, 0xC9, 0x48, 0x8B, 0x05, 0, 0,
        0, 0, 0xFF, 0xD0, 0x31, 0xC9, 0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xFF, 0xD0
    };

    std::vector<std::uint8_t> rdata;

    auto appendCString = [&rdata](const char* value) -> std::uint32_t {
        const std::uint32_t offset = static_cast<std::uint32_t>(rdata.size());
        AppendBytes(rdata, value, std::strlen(value) + 1u);
        return offset;
    };

    auto appendImportByName = [&rdata](const char* name) -> std::uint32_t {
        const std::uint32_t offset = static_cast<std::uint32_t>(rdata.size());
        const std::uint16_t hint = 0;
        AppendStruct(rdata, hint);
        AppendBytes(rdata, name, std::strlen(name) + 1u);
        if ((rdata.size() & 1u) != 0u) {
            rdata.push_back(0);
        }
        return offset;
    };

    const std::uint32_t helloOffset = appendCString("Hello world!");
    const std::uint32_t captionOffset = appendCString("Hello world!");
    while ((rdata.size() % 8u) != 0u) {
        rdata.push_back(0);
    }

    const std::uint32_t intUser32Offset = static_cast<std::uint32_t>(rdata.size());
    AppendStruct(rdata, static_cast<std::uint64_t>(0));
    AppendStruct(rdata, static_cast<std::uint64_t>(0));

    const std::uint32_t iatUser32Offset = static_cast<std::uint32_t>(rdata.size());
    AppendStruct(rdata, static_cast<std::uint64_t>(0));
    AppendStruct(rdata, static_cast<std::uint64_t>(0));

    const std::uint32_t intKernel32Offset = static_cast<std::uint32_t>(rdata.size());
    AppendStruct(rdata, static_cast<std::uint64_t>(0));
    AppendStruct(rdata, static_cast<std::uint64_t>(0));

    const std::uint32_t iatKernel32Offset = static_cast<std::uint32_t>(rdata.size());
    AppendStruct(rdata, static_cast<std::uint64_t>(0));
    AppendStruct(rdata, static_cast<std::uint64_t>(0));

    const std::uint32_t nameUser32Offset = appendCString("USER32.dll");
    const std::uint32_t nameKernel32Offset = appendCString("KERNEL32.dll");

    while ((rdata.size() % 2u) != 0u) {
        rdata.push_back(0);
    }

    const std::uint32_t importMessageBoxOffset = appendImportByName("MessageBoxA");
    const std::uint32_t importExitProcessOffset = appendImportByName("ExitProcess");

    while ((rdata.size() % 8u) != 0u) {
        rdata.push_back(0);
    }

    const std::uint32_t importTableOffset = static_cast<std::uint32_t>(rdata.size());
    IMAGE_IMPORT_DESCRIPTOR user32Desc{};
    user32Desc.OriginalFirstThunk = kRdataRva + intUser32Offset;
    user32Desc.Name = kRdataRva + nameUser32Offset;
    user32Desc.FirstThunk = kRdataRva + iatUser32Offset;

    IMAGE_IMPORT_DESCRIPTOR kernel32Desc{};
    kernel32Desc.OriginalFirstThunk = kRdataRva + intKernel32Offset;
    kernel32Desc.Name = kRdataRva + nameKernel32Offset;
    kernel32Desc.FirstThunk = kRdataRva + iatKernel32Offset;

    AppendStruct(rdata, user32Desc);
    AppendStruct(rdata, kernel32Desc);
    AppendStruct(rdata, IMAGE_IMPORT_DESCRIPTOR{});

    *reinterpret_cast<std::uint64_t*>(&rdata[intUser32Offset]) = kRdataRva + importMessageBoxOffset;
    *reinterpret_cast<std::uint64_t*>(&rdata[iatUser32Offset]) = kRdataRva + importMessageBoxOffset;
    *reinterpret_cast<std::uint64_t*>(&rdata[intKernel32Offset]) = kRdataRva + importExitProcessOffset;
    *reinterpret_cast<std::uint64_t*>(&rdata[iatKernel32Offset]) = kRdataRva + importExitProcessOffset;

    const auto writeRel32 = [&text](size_t at, std::int32_t value) {
        text[at + 0] = static_cast<std::uint8_t>((value >> 0) & 0xFF);
        text[at + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
        text[at + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
        text[at + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
    };

    const std::uint32_t instrLeaRdxRva = kTextRva + 7;   // 7-byte instruction
    const std::uint32_t instrLeaR8Rva = kTextRva + 14;   // 7-byte instruction
    const std::uint32_t instrMovMsgBoxRva = kTextRva + 24;   // 7-byte instruction
    const std::uint32_t instrMovExitProcessRva = kTextRva + 35;  // 7-byte instruction

    writeRel32(10, static_cast<std::int32_t>(kRdataRva + helloOffset) -
                       static_cast<std::int32_t>(instrLeaRdxRva + 7));
    writeRel32(17, static_cast<std::int32_t>(kRdataRva + captionOffset) -
                       static_cast<std::int32_t>(instrLeaR8Rva + 7));
    writeRel32(27, static_cast<std::int32_t>(kRdataRva + iatUser32Offset) -
                       static_cast<std::int32_t>(instrMovMsgBoxRva + 7));
    writeRel32(38, static_cast<std::int32_t>(kRdataRva + iatKernel32Offset) -
                       static_cast<std::int32_t>(instrMovExitProcessRva + 7));

    const std::uint32_t sizeOfHeaders = static_cast<std::uint32_t>(
        AlignUp(0x80 + sizeof(IMAGE_NT_HEADERS64) + 2 * sizeof(IMAGE_SECTION_HEADER), kFileAlignment));
    const std::uint32_t textRawSize = static_cast<std::uint32_t>(AlignUp(text.size(), kFileAlignment));
    const std::uint32_t rdataRawSize = static_cast<std::uint32_t>(AlignUp(rdata.size(), kFileAlignment));
    const std::uint32_t textRawPtr = sizeOfHeaders;
    const std::uint32_t rdataRawPtr = textRawPtr + textRawSize;
    const std::uint32_t sizeOfImage = static_cast<std::uint32_t>(
        AlignUp(kRdataRva + static_cast<std::uint32_t>(rdata.size()), kSectionAlignment));

    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 2;
    nt.FileHeader.TimeDateStamp = static_cast<DWORD>(std::time(nullptr));
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.AddressOfEntryPoint = kTextRva;
    nt.OptionalHeader.ImageBase = kImageBase;
    nt.OptionalHeader.SectionAlignment = kSectionAlignment;
    nt.OptionalHeader.FileAlignment = kFileAlignment;
    nt.OptionalHeader.MajorSubsystemVersion = 6;
    nt.OptionalHeader.SizeOfImage = sizeOfImage;
    nt.OptionalHeader.SizeOfHeaders = sizeOfHeaders;
    nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    nt.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    nt.OptionalHeader.SizeOfStackReserve = 1u << 20;
    nt.OptionalHeader.SizeOfStackCommit = 1u << 12;
    nt.OptionalHeader.SizeOfHeapReserve = 1u << 20;
    nt.OptionalHeader.SizeOfHeapCommit = 1u << 12;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt.OptionalHeader.SizeOfCode = static_cast<DWORD>(AlignUp(text.size(), kSectionAlignment));
    nt.OptionalHeader.SizeOfInitializedData = static_cast<DWORD>(AlignUp(rdata.size(), kSectionAlignment));
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = kRdataRva + importTableOffset;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = kRdataRva + iatUser32Offset;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 4 * sizeof(std::uint64_t);

    IMAGE_SECTION_HEADER textSec{};
    std::memcpy(textSec.Name, ".text", 5);
    textSec.Misc.VirtualSize = static_cast<DWORD>(text.size());
    textSec.VirtualAddress = kTextRva;
    textSec.SizeOfRawData = textRawSize;
    textSec.PointerToRawData = textRawPtr;
    textSec.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;

    IMAGE_SECTION_HEADER rdataSec{};
    std::memcpy(rdataSec.Name, ".rdata", 6);
    rdataSec.Misc.VirtualSize = static_cast<DWORD>(rdata.size());
    rdataSec.VirtualAddress = kRdataRva;
    rdataSec.SizeOfRawData = rdataRawSize;
    rdataSec.PointerToRawData = rdataRawPtr;
    rdataSec.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    std::vector<std::uint8_t> file(sizeOfHeaders, 0);
    std::memcpy(file.data(), &dos, sizeof(dos));
    std::memcpy(file.data() + dos.e_lfanew, &nt, sizeof(nt));
    const size_t secOffset = dos.e_lfanew + sizeof(nt);
    std::memcpy(file.data() + secOffset, &textSec, sizeof(textSec));
    std::memcpy(file.data() + secOffset + sizeof(textSec), &rdataSec, sizeof(rdataSec));

    file.insert(file.end(), text.begin(), text.end());
    AppendZeros(file, textRawSize - text.size());
    file.insert(file.end(), rdata.begin(), rdata.end());
    AppendZeros(file, rdataRawSize - rdata.size());

    std::ofstream out(outputPath, std::ios::binary);
    if (!out) {
        error = L"Failed to create output EXE file.";
        return false;
    }
    out.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
    if (!out.good()) {
        error = L"Failed to write EXE file.";
        return false;
    }
    return true;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr) {
        MessageBoxW(nullptr, L"Failed to parse command line.", L"obj2exe", MB_ICONERROR);
        return 1;
    }

    const std::wstring outputExe = (argc >= 2) ? argv[1] : L"hello.exe";
    LocalFree(argv);

    std::vector<std::uint8_t> minimalObj;
    std::wstring error;
    if (!BuildMinimalObj(minimalObj, error) || !ValidateMinimalObj(minimalObj, error)) {
        MessageBoxW(nullptr, error.c_str(), L"obj2exe: failed", MB_ICONERROR);
        return 1;
    }

    if (!BuildHelloWorldExe(outputExe, error)) {
        MessageBoxW(nullptr, error.c_str(), L"obj2exe: failed", MB_ICONERROR);
        return 1;
    }

    std::wstring ok = L"Generated EXE from internal minimal OBJ:\n" + outputExe +
                      L"\n\nRunning it will show \"Hello world!\".";
    MessageBoxW(nullptr, ok.c_str(), L"obj2exe", MB_OK | MB_ICONINFORMATION);
    return 0;
}
