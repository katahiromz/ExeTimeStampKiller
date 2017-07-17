// ExeTimeStampKiller.cpp --- Deletes EXE timestamps
// Copyright (C) 2017 Katayama Hirofumi MZ.
// This software is public domain software (PDS).
////////////////////////////////////////////////////////////////////////////

#if defined(UNICODE) && !defined(_UNICODE)
    #define _UNICODE 1
#endif
#if !defined(UNICODE) && defined(_UNICODE)
    #define UNICODE 1
#endif

#include <cstdio>
#include <vector>
#include <tchar.h>

#include "MFileMapping.hpp"
#include "pdelayimp.h"

using namespace std;

////////////////////////////////////////////////////////////////////////////

BOOL g_bIs64Bit = FALSE;

void eprintf(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vfprintf(stderr, fmt, va);
    fflush(stderr);
    va_end(va);
}

enum EXITCODE
{
    EC_SUCCESS = 0,
    EC_CANNOTOPEN,
    EC_CANNOTREAD,
    EC_INVALIDFORMAT,
    EC_INVALIDARG
};

////////////////////////////////////////////////////////////////////////////

struct SECTION_ENTRY
{
    char    Name[IMAGE_SIZEOF_SHORT_NAME + 1];
    DWORD   Size;
    DWORD   RVA;
    DWORD   DataSize;
    DWORD   DataOffset;
    DWORD   Flags;

    SECTION_ENTRY(const IMAGE_SECTION_HEADER *header)
    {
        CopyMemory(Name, header->Name, IMAGE_SIZEOF_SHORT_NAME);
        Name[IMAGE_SIZEOF_SHORT_NAME] = 0;
        Size = header->Misc.VirtualSize;
        RVA = header->VirtualAddress;
        DataSize = header->SizeOfRawData;
        DataOffset = header->PointerToRawData;
        Flags = header->Characteristics;
    }
};

////////////////////////////////////////////////////////////////////////////

struct SECTION_INFO
{
    DWORD m_header_size;
    std::vector<SECTION_ENTRY> m_entries;

    size_t size() const
    {
        return m_entries.size();
    }
    SECTION_ENTRY& operator[](size_t index)
    {
        return m_entries[index];
    }
    const SECTION_ENTRY& operator[](size_t index) const
    {
        return m_entries[index];
    }

    SECTION_INFO(DWORD SizeOfHeaders,
                 const IMAGE_SECTION_HEADER *headers, DWORD count)
    {
        m_header_size = SizeOfHeaders;
        m_entries.clear();
        for (DWORD i = 0; i < count; ++i)
        {
            SECTION_ENTRY entry(&headers[i]);
            m_entries.push_back(entry);
        }
    }

    void Dump() const
    {
        eprintf("#   Name      VirtSize    RVA     PhysSize  Phys off  Flags   \n");
        for (size_t i = 0; i < m_entries.size(); ++i)
        {
            const SECTION_ENTRY *entry = &m_entries[i];
            eprintf("%02d  %-8s  %08X  %08X  %08X  %08X  %08X\n",
                INT(i), entry->Name, entry->Size, entry->RVA,
                entry->DataSize, entry->DataOffset, entry->Flags);
        }
    }

    DWORD OffsetFromRVA(DWORD rva) const
    {
        if (rva < m_header_size)
            return rva;

        for (size_t i = 0; i < m_entries.size(); ++i)
        {
            const SECTION_ENTRY *entry = &m_entries[i];
            if (entry->RVA <= rva && rva < entry->RVA + entry->DataSize)
            {
                return entry->DataOffset + rva - entry->RVA;
            }
        }
        return 0xFFFFFFFF;
    }
};

////////////////////////////////////////////////////////////////////////////

INT DoSymbol(MFileMapping& mapping, DWORD PointerToSymbolTable, DWORD NumberOfSymbols)
{
    if (NumberOfSymbols == 0 || PointerToSymbolTable == 0)
        return EC_SUCCESS;

    DWORDLONG pos = mapping.GetPos64();

    // FIXME
    mapping.Seek64(pos, TRUE);

    return EC_SUCCESS;
}

INT DoFileHeader(MFileMapping& mapping, IMAGE_FILE_HEADER& file)
{
    eprintf("[IMAGE_FILE_HEADER]\n");
    eprintf("Machine: 0x%04X\n", file.Machine);
    eprintf("NumberOfSections: 0x%04X\n", file.NumberOfSections);
    eprintf("TimeDateStamp: 0x%08lX\n", file.TimeDateStamp);
    eprintf("PointerToSymbolTable: 0x%08lX\n", file.PointerToSymbolTable);
    eprintf("NumberOfSymbols: 0x%08lX\n", file.NumberOfSymbols);
    eprintf("SizeOfOptionalHeader: 0x%04X\n", file.SizeOfOptionalHeader);
    eprintf("Characteristics: 0x%04X\n", file.Characteristics);

    file.TimeDateStamp = 0;

    DWORD PointerToSymbolTable = file.PointerToSymbolTable;
    DWORD NumberOfSymbols = file.NumberOfSymbols;
    if (NumberOfSymbols)
    {
        INT ret = DoSymbol(mapping, PointerToSymbolTable, NumberOfSymbols);
        if (ret)
            return ret;
    }

    return EC_SUCCESS;
}

INT DoExp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    MTypedMapView<IMAGE_EXPORT_DIRECTORY> exp;
    mapping.Seek64(offset, TRUE);
    exp = mapping.GetTypedData<IMAGE_EXPORT_DIRECTORY>();
    if (!exp)
    {
        eprintf("ERROR: Unable to read\n");
        return EC_CANNOTREAD;
    }

    eprintf("[IMAGE_EXPORT_DIRECTORY]\n");
    eprintf("Characteristics: 0x08lX\n", exp->Characteristics);
    eprintf("TimeDateStamp: 0x08lX\n", exp->TimeDateStamp);
    eprintf("MajorVersion: 0x04X\n", exp->MajorVersion);
    eprintf("MinorVersion: 0x04X\n", exp->MinorVersion);
    eprintf("Name: 0x08lX\n", exp->Name);
    eprintf("Base: 0x08lX\n", exp->Base);
    eprintf("NumberOfFunctions: 0x08lX\n", exp->NumberOfFunctions);
    eprintf("NumberOfNames: 0x08lX\n", exp->NumberOfNames);
    eprintf("AddressOfFunctions: 0x08lX\n", exp->AddressOfFunctions);
    eprintf("AddressOfNames: 0x08lX\n", exp->AddressOfNames);
    eprintf("AddressOfNameOrdinals: 0x08lX\n", exp->AddressOfNameOrdinals);

    exp->TimeDateStamp = 0;
    return EC_SUCCESS;
}

INT DoImp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);
    const DWORD count = size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    MTypedMapView<IMAGE_IMPORT_DESCRIPTOR> imp;
    imp = mapping.GetTypedData<IMAGE_IMPORT_DESCRIPTOR>(size);
    if (!imp)
    {
        eprintf("ERROR: Unable to read\n");
        return EC_CANNOTREAD;
    }

    for (DWORD i = 0; i < count; ++i)
    {
        MTypedMapView<IMAGE_IMPORT_DESCRIPTOR> desc;
        desc = mapping.GetTypedData<IMAGE_IMPORT_DESCRIPTOR>();
        if (!desc)
        {
            eprintf("ERROR: Unable to read\n");
            return EC_CANNOTREAD;
        }

        eprintf("[IMAGE_IMPORT_DESCRIPTOR #%lu]", i);
        eprintf("Characteristics: 0x%08lX\n", desc->Characteristics);
        eprintf("OriginalFirstThunk: 0x%08lX\n", desc->OriginalFirstThunk);
        eprintf("TimeDateStamp: 0x%08lX\n", desc->TimeDateStamp);
        eprintf("ForwarderChain: 0x%08lX\n", desc->ForwarderChain);
        eprintf("Name: 0x%08lX\n", desc->Name);
        eprintf("FirstThunk: 0x%08lX\n", desc->FirstThunk);

        desc->TimeDateStamp = 0;
        if (desc->Characteristics == 0)
            break;

        mapping.Seek64(sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    return EC_SUCCESS;
}

INT DoResDir(MFileMapping& mapping, SECTION_INFO& sec_info,
             DWORD res_offset, IMAGE_RESOURCE_DIRECTORY& dir);

INT DoResEnt(MFileMapping& mapping, SECTION_INFO& sec_info,
             DWORD res_offset, IMAGE_RESOURCE_DIRECTORY_ENTRY& ent)
{
    if (ent.DataIsDirectory)
    {
        mapping.Seek64(res_offset + ent.OffsetToDirectory, TRUE);

        MTypedMapView<IMAGE_RESOURCE_DIRECTORY> dir;
        dir = mapping.GetTypedData<IMAGE_RESOURCE_DIRECTORY>();
        if (!dir)
        {
            eprintf("ERROR: Unable to read\n");
            return EC_CANNOTREAD;
        }

        return DoResDir(mapping, sec_info, res_offset, *dir);
    }
    else
    {
        mapping.Seek64(res_offset + ent.OffsetToData, TRUE);

        MTypedMapView<IMAGE_RESOURCE_DATA_ENTRY> data;
        data = mapping.GetTypedData<IMAGE_RESOURCE_DATA_ENTRY>();
        if (!data)
        {
            eprintf("ERROR: Unable to read\n");
            return EC_CANNOTREAD;
        }

        // FIXME

        return EC_SUCCESS;
    }
}

INT DoResDir(MFileMapping& mapping, SECTION_INFO& sec_info,
             DWORD res_offset, IMAGE_RESOURCE_DIRECTORY& dir)
{
    dir.TimeDateStamp = 0;
    mapping.Seek64(sizeof(IMAGE_RESOURCE_DIRECTORY));

    DWORD num_entries = dir.NumberOfNamedEntries + dir.NumberOfIdEntries;
    if (num_entries == 0)
        return EC_SUCCESS;

    DWORD ent_size = num_entries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    MTypedMapView<IMAGE_RESOURCE_DIRECTORY_ENTRY> entries;
    entries = mapping.GetTypedData<IMAGE_RESOURCE_DIRECTORY_ENTRY>(ent_size);
    if (!entries)
    {
        eprintf("ERROR: Unable to read\n");
        return EC_CANNOTREAD;
    }

    for (DWORD i = 0; i < num_entries; ++i)
    {
        IMAGE_RESOURCE_DIRECTORY_ENTRY& ent = entries[i];
        INT ret = DoResEnt(mapping, sec_info, res_offset, ent);
        if (ret)
            return ret;
    }

    return EC_SUCCESS;
}

INT DoRes(MFileMapping& mapping, SECTION_INFO& sec_info, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);

    MTypedMapView<IMAGE_RESOURCE_DIRECTORY> dir;
    dir = mapping.GetTypedData<IMAGE_RESOURCE_DIRECTORY>();
    if (!dir)
    {
        eprintf("ERROR: Unable to read\n");
        return EC_CANNOTREAD;
    }

    return DoResDir(mapping, sec_info, offset, *dir);
}

INT DoLoadConfig32(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);

    MTypedMapView<IMAGE_LOAD_CONFIG_DIRECTORY32> config;
    config = mapping.GetTypedData<IMAGE_LOAD_CONFIG_DIRECTORY32>();
    if (!config)
    {
        eprintf("ERROR: Unable to read\n");
        return EC_CANNOTREAD;
    }

    config->TimeDateStamp = 0;
    return EC_SUCCESS;
}

INT DoLoadConfig64(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);

    MTypedMapView<IMAGE_LOAD_CONFIG_DIRECTORY64> config;
    config = mapping.GetTypedData<IMAGE_LOAD_CONFIG_DIRECTORY64>();
    if (!config)
    {
        eprintf("ERROR: Unable to read\n");
        return EC_CANNOTREAD;
    }

    config->TimeDateStamp = 0;
    return EC_SUCCESS;
}

INT DoLoadConfig(MFileMapping& mapping, DWORD offset, DWORD size)
{
    if (g_bIs64Bit)
    {
        return DoLoadConfig64(mapping, offset, size);
    }
    else
    {
        return DoLoadConfig32(mapping, offset, size);
    }
}

INT DoDebug(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);

    DWORD count = size / sizeof(IMAGE_DEBUG_DIRECTORY);

    MTypedMapView<IMAGE_DEBUG_DIRECTORY> debug;
    debug = mapping.GetTypedData<IMAGE_DEBUG_DIRECTORY>(size);
    if (!debug)
    {
        eprintf("ERROR: Unable to read\n");
        return EC_CANNOTREAD;
    }

    for (DWORD i = 0; i < count; ++i)
    {
        debug[i].TimeDateStamp = 0;
    }

    return EC_SUCCESS;
}

INT DoBoundImp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);

    MTypedMapView<IMAGE_BOUND_IMPORT_DESCRIPTOR> desc;
    MTypedMapView<IMAGE_BOUND_FORWARDER_REF> ref;

    DWORDLONG pos = offset;
    for (;;)
    {
        if (pos + size <= offset + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR))
            break;

        desc = mapping.GetTypedData<IMAGE_BOUND_IMPORT_DESCRIPTOR>();
        if (!desc)
        {
            eprintf("ERROR: Unable to read\n");
            return EC_CANNOTREAD;
        }
        desc->TimeDateStamp = 0;
        pos += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);

        DWORD dwNumRefs = desc->NumberOfModuleForwarderRefs;
        DWORD ref_size = dwNumRefs * sizeof(IMAGE_BOUND_FORWARDER_REF);
        ref = mapping.GetTypedData<IMAGE_BOUND_FORWARDER_REF>(ref_size);
        if (!ref)
        {
            eprintf("ERROR: Unable to read\n");
            return EC_CANNOTREAD;
        }
        for (DWORD i = 0; i < dwNumRefs; ++i)
        {
            ref[i].TimeDateStamp = 0;
        }
        pos += ref_size;
    }

    return EC_SUCCESS;
}

INT DoDelayImp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);

    MTypedMapView<ImgDelayDescr> descr;
    descr = mapping.GetTypedData<ImgDelayDescr>();
    if (!descr)
    {
        eprintf("ERROR: Unable to read\n");
        return EC_CANNOTREAD;
    }

    descr->dwTimeStamp = 0;

    return EC_SUCCESS;
}

INT DoSect(MFileMapping& mapping, SECTION_INFO& sec_info,
           IMAGE_DATA_DIRECTORY *pDir)
{
    sec_info.Dump();

    IMAGE_DATA_DIRECTORY *data;
    DWORD offset, size;
    INT ret;

    data = &pDir[IMAGE_DIRECTORY_ENTRY_EXPORT];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoExp(mapping, offset, size);
        if (ret)
            return ret;
        eprintf("DoExp.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoImp(mapping, offset, size);
        if (ret)
            return ret;
        eprintf("DoImp.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoRes(mapping, sec_info, offset, size);
        if (ret)
            return ret;
        eprintf("DoRes.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoLoadConfig(mapping, offset, size);
        if (ret)
            return ret;
        eprintf("DoLoadConfig.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_DEBUG];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoDebug(mapping, offset, size);
        if (ret)
            return ret;
        eprintf("DoDebug.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoBoundImp(mapping, offset, size);
        if (ret)
            return ret;
        eprintf("DoBoundImp.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoDelayImp(mapping, offset, size);
        if (ret)
            return ret;
        eprintf("DoDelayImp.\n");
    }

    return EC_SUCCESS;
}

INT DoNT32(MFileMapping& mapping, IMAGE_NT_HEADERS32& nt32)
{
    IMAGE_OPTIONAL_HEADER32& opt32 = nt32.OptionalHeader;
    if (opt32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        eprintf("ERROR: Invalid executable file\n");
        return EC_INVALIDFORMAT;
    }
    opt32.CheckSum = 0;

    IMAGE_FILE_HEADER& file = nt32.FileHeader;
    WORD NumberOfSections = file.NumberOfSections;
    INT ret = DoFileHeader(mapping, file);
    if (ret)
        return ret;

    MTypedMapView<IMAGE_SECTION_HEADER> sections;
    DWORD sect_total = NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    sections = mapping.GetTypedData<IMAGE_SECTION_HEADER>(sect_total);
    if (!sections)
    {
        eprintf("ERROR: Unable to read\n");
        return EC_CANNOTREAD;
    }

    SECTION_INFO sec_info(opt32.SizeOfHeaders, sections, NumberOfSections);
    return DoSect(mapping, sec_info, opt32.DataDirectory);
}

INT DoNT64(MFileMapping& mapping, IMAGE_NT_HEADERS64& nt64)
{
    IMAGE_OPTIONAL_HEADER64& opt64 = nt64.OptionalHeader;
    if (opt64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        eprintf("ERROR: Invalid executable file\n");
        return EC_INVALIDFORMAT;
    }
    opt64.CheckSum = 0;

    IMAGE_FILE_HEADER& file = nt64.FileHeader;
    WORD NumberOfSections = file.NumberOfSections;
    INT ret = DoFileHeader(mapping, file);
    if (ret)
        return ret;

    MTypedMapView<IMAGE_SECTION_HEADER> sections;
    DWORD sect_total = NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    sections = mapping.GetTypedData<IMAGE_SECTION_HEADER>(sect_total);
    if (!sections)
    {
        eprintf("ERROR: Unable to read\n");
        return EC_CANNOTREAD;
    }

    SECTION_INFO sec_info(opt64.SizeOfHeaders, sections, NumberOfSections);
    return DoSect(mapping, sec_info, opt64.DataDirectory);
}

INT DoMap(HANDLE hFile)
{
    MFileMapping mapping;

    if (!mapping.CreateFileMapping(hFile))
    {
        eprintf("ERROR: Unable to open file\n");
        return EC_CANNOTOPEN;
    }
    eprintf("Mapped.\n");

    {
        MTypedMapView<IMAGE_DOS_HEADER> dos;
        dos = mapping.GetTypedData<IMAGE_DOS_HEADER>();
        if (!dos)
        {
            eprintf("ERROR: Invalid executable file\n");
            return EC_INVALIDFORMAT;
        }

        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            mapping.Seek64(dos->e_lfanew);
            eprintf("DOS Header.\n");
        }
    }

    DWORD SizeOfOptionalHeader;
    {
        MTypedMapView<IMAGE_NT_HEADERS32> nt32;
        nt32 = mapping.GetTypedData<IMAGE_NT_HEADERS32>();
        if (!nt32)
        {
            eprintf("ERROR: Unable to read\n");
            return EC_CANNOTREAD;
        }
        eprintf("NT Header.\n");
        if (nt32->Signature != IMAGE_NT_SIGNATURE)
        {
            eprintf("ERROR: Invalid executable file\n");
            return EC_INVALIDFORMAT;
        }
        SizeOfOptionalHeader = nt32->FileHeader.SizeOfOptionalHeader;
        eprintf("SizeOfOptionalHeader: %d.\n", SizeOfOptionalHeader);
    }

    if (SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        g_bIs64Bit = FALSE;
        MTypedMapView<IMAGE_NT_HEADERS32> nt32;
        nt32 = mapping.GetTypedData<IMAGE_NT_HEADERS32>();
        if (!nt32)
        {
            eprintf("ERROR: Unable to read\n");
            return EC_CANNOTREAD;
        }
        eprintf("NT32.\n");
        mapping.Seek64(sizeof(IMAGE_NT_HEADERS32));
        return DoNT32(mapping, *nt32);
    }
    else if (SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        g_bIs64Bit = TRUE;
        MTypedMapView<IMAGE_NT_HEADERS64> nt64;
        nt64 = mapping.GetTypedData<IMAGE_NT_HEADERS64>();
        if (!nt64)
        {
            eprintf("ERROR: Unable to read\n");
            return EC_CANNOTREAD;
        }
        eprintf("NT64.\n");
        mapping.Seek64(sizeof(IMAGE_NT_HEADERS64));
        return DoNT64(mapping, *nt64);
    }

    eprintf("ERROR: Unknown executable format\n");
    return EC_INVALIDFORMAT;
}

////////////////////////////////////////////////////////////////////////////

INT JustDoIt(const TCHAR *pszFileName)
{
    HANDLE hFile;

    hFile = CreateFile(pszFileName, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        eprintf("ERROR: Unable to open file\n");
        return EC_CANNOTOPEN;
    }
    eprintf("Opened.\n");

    INT ret = DoMap(hFile);
    CloseHandle(hFile);
    eprintf("Closed.\n");

    return ret;
}

extern "C"
INT _tmain(INT argc, TCHAR **targv)
{
    if (argc != 2)
    {
        printf("Usage: ExeTimestampKiller file.exe\n");
        return EC_INVALIDARG;
    }

    return JustDoIt(targv[1]);
}

////////////////////////////////////////////////////////////////////////////
