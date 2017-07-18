// ExeTimeStampKiller.cpp --- Resets the timestamps in an EXE or DLL file
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

BOOL g_bIs64Bit;
BOOL g_bVerbose;
DWORD g_dwTimeStamp;
TCHAR *g_target;

VOID ShowVersion(VOID)
{
    printf("ExeTimeStampKiller Version 0.3 / 2017.07.18\n");
    printf("Written by Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>.\n");
    printf("This software is public domain software (PDS).\n");
}

void ShowHelp(void)
{
    printf("Usage: ExeTimestampKiller [options] file.exe\n");
    printf("Options:\n");
    printf("-n              Set now.\n");
    printf("-d YYYYMMDD     Set date.\n");
    printf("-t HHmmss       Set time.\n");
    printf("-v              Verbose output.\n");
    printf("-x XXXXXXXX     Set hexidemical timestamp value to set.\n");
    printf("--help          Show this help.\n");
    printf("--version       Show version.\n");
}

////////////////////////////////////////////////////////////////////////////

void eprintf(const char *fmt, ...)
{
    char buf[1024];

    va_list va;
    va_start(va, fmt);
    wvsprintfA(buf, fmt, va);
    va_end(va);

    fputs(buf, stderr);
    fflush(stderr);
}

void dprintf(const char *fmt, ...)
{
    if (!g_bVerbose)
        return;

    char buf[1024];
    va_list va;
    va_start(va, fmt);
    wvsprintfA(buf, fmt, va);
    va_end(va);

    fputs(buf, stderr);
    fflush(stderr);
}

enum RETURNCODE
{
    RET_SUCCESS = 0,
    RET_CANNOTOPEN,
    RET_CANNOTREAD,
    RET_INVALIDFORMAT,
    RET_INVALIDARG,
    RET_SHOWHELP,
    RET_SHOWVERSION
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
        dprintf("#   Name      VirtSize    RVA     PhysSize  Phys off  Flags   \n");
        for (size_t i = 0; i < m_entries.size(); ++i)
        {
            const SECTION_ENTRY *entry = &m_entries[i];
            dprintf("%02d  %-8s  %08X  %08X  %08X  %08X  %08X\n",
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
        return RET_SUCCESS;

    DWORDLONG pos = mapping.GetPos64();

    // FIXME
    mapping.Seek64(pos, TRUE);

    return RET_SUCCESS;
}

INT DoFileHeader(MFileMapping& mapping, IMAGE_FILE_HEADER& file)
{
    dprintf("[IMAGE_FILE_HEADER]\n");
    dprintf("Machine: 0x%04X\n", file.Machine);
    dprintf("NumberOfSections: 0x%04X\n", file.NumberOfSections);
    dprintf("TimeDateStamp: 0x%08lX\n", file.TimeDateStamp);
    dprintf("PointerToSymbolTable: 0x%08lX\n", file.PointerToSymbolTable);
    dprintf("NumberOfSymbols: 0x%08lX\n", file.NumberOfSymbols);
    dprintf("SizeOfOptionalHeader: 0x%04X\n", file.SizeOfOptionalHeader);
    dprintf("Characteristics: 0x%04X\n", file.Characteristics);

    file.TimeDateStamp = g_dwTimeStamp;

    DWORD PointerToSymbolTable = file.PointerToSymbolTable;
    DWORD NumberOfSymbols = file.NumberOfSymbols;
    if (NumberOfSymbols)
    {
        INT ret = DoSymbol(mapping, PointerToSymbolTable, NumberOfSymbols);
        if (ret)
            return ret;
    }

    return RET_SUCCESS;
}

INT DoExp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    MTypedMapView<IMAGE_EXPORT_DIRECTORY> exp;
    mapping.Seek64(offset, TRUE);
    exp = mapping.GetTypedData<IMAGE_EXPORT_DIRECTORY>();
    if (!exp)
    {
        eprintf("ERROR: Unable to read\n");
        return RET_CANNOTREAD;
    }

    dprintf("[IMAGE_EXPORT_DIRECTORY @ 0x%08lX]\n", offset);
    dprintf("Characteristics: 0x08lX\n", exp->Characteristics);
    dprintf("TimeDateStamp: 0x08lX\n", exp->TimeDateStamp);
    dprintf("MajorVersion: 0x04X\n", exp->MajorVersion);
    dprintf("MinorVersion: 0x04X\n", exp->MinorVersion);
    dprintf("Name: 0x08lX\n", exp->Name);
    dprintf("Base: 0x08lX\n", exp->Base);
    dprintf("NumberOfFunctions: 0x08lX\n", exp->NumberOfFunctions);
    dprintf("NumberOfNames: 0x08lX\n", exp->NumberOfNames);
    dprintf("AddressOfFunctions: 0x08lX\n", exp->AddressOfFunctions);
    dprintf("AddressOfNames: 0x08lX\n", exp->AddressOfNames);
    dprintf("AddressOfNameOrdinals: 0x08lX\n", exp->AddressOfNameOrdinals);

    exp->TimeDateStamp = g_dwTimeStamp;
    return RET_SUCCESS;
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
        return RET_CANNOTREAD;
    }

    for (DWORD i = 0; i < count; ++i)
    {
        MTypedMapView<IMAGE_IMPORT_DESCRIPTOR> desc;
        desc = mapping.GetTypedData<IMAGE_IMPORT_DESCRIPTOR>();
        if (!desc)
        {
            eprintf("ERROR: Unable to read\n");
            return RET_CANNOTREAD;
        }

        dprintf("[IMAGE_IMPORT_DESCRIPTOR #%lu @ 0x%08lX]\n", i, mapping.GetPos());
        dprintf("Characteristics: 0x%08lX\n", desc->Characteristics);
        dprintf("OriginalFirstThunk: 0x%08lX\n", desc->OriginalFirstThunk);
        dprintf("TimeDateStamp: 0x%08lX\n", desc->TimeDateStamp);
        dprintf("ForwarderChain: 0x%08lX\n", desc->ForwarderChain);
        dprintf("Name: 0x%08lX\n", desc->Name);
        dprintf("FirstThunk: 0x%08lX\n", desc->FirstThunk);

        desc->TimeDateStamp = g_dwTimeStamp;
        if (desc->Characteristics == 0)
            break;

        mapping.Seek64(sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    return RET_SUCCESS;
}

INT DoResDir(MFileMapping& mapping, SECTION_INFO& sec_info,
             DWORD res_offset, IMAGE_RESOURCE_DIRECTORY& dir, DWORD pos);

INT DoResEnt(MFileMapping& mapping, SECTION_INFO& sec_info,
             DWORD res_offset, IMAGE_RESOURCE_DIRECTORY_ENTRY& ent,
             DWORD pos)
{
    dprintf("[IMAGE_RESOURCE_DIRECTORY_ENTRY @ 0x%08lX]\n", pos);
    if (ent.NameIsString)
    {
        dprintf("name is string\n");
        dprintf("NameOffset: 0x%08lX\n", ent.NameOffset);
    }
    else
    {
        dprintf("name is not string\n");
        dprintf("Id: 0x%04X\n", ent.Id);
    }

    if (ent.DataIsDirectory)
    {
        dprintf("data is directory\n");
        dprintf("OffsetToDirectory: 0x%08lX\n", ent.OffsetToDirectory);

        DWORD pos = res_offset + ent.OffsetToDirectory;
        mapping.Seek64(pos, TRUE);

        MTypedMapView<IMAGE_RESOURCE_DIRECTORY> dir;
        dir = mapping.GetTypedData<IMAGE_RESOURCE_DIRECTORY>();
        if (!dir)
        {
            eprintf("ERROR: Unable to read\n");
            return RET_CANNOTREAD;
        }

        return DoResDir(mapping, sec_info, res_offset, *dir, pos);
    }
    else
    {
        dprintf("data is not directory\n");
        dprintf("OffsetToData: 0x%08lX\n", ent.OffsetToData);

        mapping.Seek64(res_offset + ent.OffsetToData, TRUE);

        MTypedMapView<IMAGE_RESOURCE_DATA_ENTRY> data;
        data = mapping.GetTypedData<IMAGE_RESOURCE_DATA_ENTRY>();
        if (!data)
        {
            eprintf("ERROR: Unable to read\n");
            return RET_CANNOTREAD;
        }

        // FIXME

        return RET_SUCCESS;
    }
}

INT DoResDir(MFileMapping& mapping, SECTION_INFO& sec_info,
             DWORD res_offset, IMAGE_RESOURCE_DIRECTORY& dir, DWORD pos)
{
    dprintf("[IMAGE_RESOURCE_DIRECTORY @ 0x%08lX]: \n", pos);
    dprintf("Characteristics: 0x%08lX\n", dir.Characteristics);
    dprintf("TimeDateStamp: 0x%08lX\n", dir.TimeDateStamp);
    dprintf("MajorVersion: 0x%04X\n", dir.MajorVersion);
    dprintf("MinorVersion: 0x%04X\n", dir.MinorVersion);
    dprintf("NumberOfNamedEntries: 0x%04X\n", dir.NumberOfNamedEntries);
    dprintf("NumberOfIdEntries: 0x%04X\n", dir.NumberOfIdEntries);

    dir.TimeDateStamp = g_dwTimeStamp;
    mapping.Seek64(sizeof(IMAGE_RESOURCE_DIRECTORY));

    DWORD num_entries = dir.NumberOfNamedEntries + dir.NumberOfIdEntries;
    if (num_entries == 0)
        return RET_SUCCESS;

    DWORD ent_size = num_entries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
    MTypedMapView<IMAGE_RESOURCE_DIRECTORY_ENTRY> entries;
    entries = mapping.GetTypedData<IMAGE_RESOURCE_DIRECTORY_ENTRY>(ent_size);
    if (!entries)
    {
        eprintf("ERROR: Unable to read\n");
        return RET_CANNOTREAD;
    }

    for (DWORD i = 0; i < num_entries; ++i)
    {
        IMAGE_RESOURCE_DIRECTORY_ENTRY& ent = entries[i];
        DWORD pos = mapping.GetPos() + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
        INT ret = DoResEnt(mapping, sec_info, res_offset, ent, pos);
        if (ret)
            return ret;
    }

    return RET_SUCCESS;
}

INT DoRes(MFileMapping& mapping, SECTION_INFO& sec_info, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);

    MTypedMapView<IMAGE_RESOURCE_DIRECTORY> dir;
    dir = mapping.GetTypedData<IMAGE_RESOURCE_DIRECTORY>();
    if (!dir)
    {
        eprintf("ERROR: Unable to read\n");
        return RET_CANNOTREAD;
    }

    return DoResDir(mapping, sec_info, offset, *dir, offset);
}

INT DoLoadConfig32(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);

    MTypedMapView<IMAGE_LOAD_CONFIG_DIRECTORY32> config;
    config = mapping.GetTypedData<IMAGE_LOAD_CONFIG_DIRECTORY32>();
    if (!config)
    {
        eprintf("ERROR: Unable to read\n");
        return RET_CANNOTREAD;
    }

    config->TimeDateStamp = g_dwTimeStamp;
    return RET_SUCCESS;
}

INT DoLoadConfig64(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);

    MTypedMapView<IMAGE_LOAD_CONFIG_DIRECTORY64> config;
    config = mapping.GetTypedData<IMAGE_LOAD_CONFIG_DIRECTORY64>();
    if (!config)
    {
        eprintf("ERROR: Unable to read\n");
        return RET_CANNOTREAD;
    }

    config->TimeDateStamp = g_dwTimeStamp;
    return RET_SUCCESS;
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
        return RET_CANNOTREAD;
    }

    for (DWORD i = 0; i < count; ++i)
    {
        dprintf("[IMAGE_DEBUG_DIRECTORY #%lu]\n", i);
        dprintf("Characteristics: 0x%08lX\n", debug[i].Characteristics);
        dprintf("TimeDateStamp: 0x%08lX\n", debug[i].TimeDateStamp);
        dprintf("MajorVersion: 0x%04X\n", debug[i].MajorVersion);
        dprintf("MinorVersion: 0x%04X\n", debug[i].MinorVersion);
        dprintf("Type: 0x%08lX\n", debug[i].Type);
        dprintf("SizeOfData: 0x%08lX\n", debug[i].SizeOfData);
        dprintf("AddressOfRawData: 0x%08lX\n", debug[i].AddressOfRawData);
        dprintf("PointerToRawData: 0x%08lX\n", debug[i].PointerToRawData);
        debug[i].TimeDateStamp = g_dwTimeStamp;
    }

    return RET_SUCCESS;
}

INT DoBoundImp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    MTypedMapView<IMAGE_BOUND_IMPORT_DESCRIPTOR> desc;
    MTypedMapView<IMAGE_BOUND_FORWARDER_REF> ref;

    DWORDLONG pos = offset;
    for (;;)
    {
        if (offset + size < pos + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR))
            break;

        mapping.Seek64(pos, TRUE);
        desc = mapping.GetTypedData<IMAGE_BOUND_IMPORT_DESCRIPTOR>();
        if (!desc)
        {
            eprintf("ERROR: Unable to read\n");
            return RET_CANNOTREAD;
        }

        dprintf("[IMAGE_BOUND_IMPORT_DESCRIPTOR @ 0x%08lX]\n", pos);
        dprintf("TimeDateStamp: 0x%08lX\n", desc->TimeDateStamp);
        dprintf("OffsetModuleName: 0x%04X\n", desc->OffsetModuleName);
        dprintf("NumberOfModuleForwarderRefs: 0x%04X\n", desc->NumberOfModuleForwarderRefs);

        desc->TimeDateStamp = g_dwTimeStamp;
        pos += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);

        DWORD count = desc->NumberOfModuleForwarderRefs;
        DWORD ref_size = count * sizeof(IMAGE_BOUND_FORWARDER_REF);
        if (offset + size < pos + ref_size)
            break;

        mapping.Seek64(pos, TRUE);
        ref = mapping.GetTypedData<IMAGE_BOUND_FORWARDER_REF>(ref_size);
        if (!ref)
        {
            eprintf("ERROR: Unable to read\n");
            return RET_CANNOTREAD;
        }
        for (DWORD i = 0; i < count; ++i)
        {
            dprintf("[IMAGE_BOUND_FORWARDER_REF #%lu @ 0x%08lX]\n", i, pos);
            dprintf("TimeDateStamp: 0x%08lX\n", ref[i].TimeDateStamp);
            dprintf("OffsetModuleName: 0x%04X\n", ref[i].OffsetModuleName);
            dprintf("Reserved: 0x%04X\n", ref[i].Reserved);

            ref[i].TimeDateStamp = g_dwTimeStamp;
            pos += sizeof(IMAGE_BOUND_FORWARDER_REF);
        }
    }

    return RET_SUCCESS;
}

INT DoDelayImp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.Seek64(offset, TRUE);

    MTypedMapView<ImgDelayDescr> descr;
    descr = mapping.GetTypedData<ImgDelayDescr>();
    if (!descr)
    {
        eprintf("ERROR: Unable to read\n");
        return RET_CANNOTREAD;
    }

    descr->dwTimeStamp = 0;

    return RET_SUCCESS;
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
        dprintf("DoExp done.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoImp(mapping, offset, size);
        if (ret)
            return ret;
        dprintf("DoImp done.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoRes(mapping, sec_info, offset, size);
        if (ret)
            return ret;
        dprintf("DoRes done.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoLoadConfig(mapping, offset, size);
        if (ret)
            return ret;
        dprintf("DoLoadConfig done.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_DEBUG];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoDebug(mapping, offset, size);
        if (ret)
            return ret;
        dprintf("DoDebug done.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoBoundImp(mapping, offset, size);
        if (ret)
            return ret;
        dprintf("DoBoundImp done.\n");
    }

    data = &pDir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    offset = sec_info.OffsetFromRVA(data->VirtualAddress);
    size = data->Size;
    if (offset && size && offset != 0xFFFFFFFF)
    {
        ret = DoDelayImp(mapping, offset, size);
        if (ret)
            return ret;
        dprintf("DoDelayImp done.\n");
    }

    return RET_SUCCESS;
}

INT DoNT32(MFileMapping& mapping, IMAGE_NT_HEADERS32& nt32)
{
    IMAGE_OPTIONAL_HEADER32& opt32 = nt32.OptionalHeader;
    if (opt32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        eprintf("ERROR: Invalid executable file\n");
        return RET_INVALIDFORMAT;
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
        return RET_CANNOTREAD;
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
        return RET_INVALIDFORMAT;
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
        return RET_CANNOTREAD;
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
        return RET_CANNOTOPEN;
    }
    dprintf("Mapped.\n");

    {
        MTypedMapView<IMAGE_DOS_HEADER> dos;
        dos = mapping.GetTypedData<IMAGE_DOS_HEADER>();
        if (!dos)
        {
            eprintf("ERROR: Invalid executable file\n");
            return RET_INVALIDFORMAT;
        }

        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            mapping.Seek64(dos->e_lfanew);
            dprintf("DOS Header done.\n");
        }
    }

    DWORD SizeOfOptionalHeader;
    {
        MTypedMapView<IMAGE_NT_HEADERS32> nt32;
        nt32 = mapping.GetTypedData<IMAGE_NT_HEADERS32>();
        if (!nt32)
        {
            eprintf("ERROR: Unable to read\n");
            return RET_CANNOTREAD;
        }
        dprintf("NT Header done.\n");
        if (nt32->Signature != IMAGE_NT_SIGNATURE)
        {
            eprintf("ERROR: Invalid executable file\n");
            return RET_INVALIDFORMAT;
        }
        SizeOfOptionalHeader = nt32->FileHeader.SizeOfOptionalHeader;
        dprintf("SizeOfOptionalHeader: %d.\n", SizeOfOptionalHeader);
    }

    if (SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        g_bIs64Bit = FALSE;
        MTypedMapView<IMAGE_NT_HEADERS32> nt32;
        nt32 = mapping.GetTypedData<IMAGE_NT_HEADERS32>();
        if (!nt32)
        {
            eprintf("ERROR: Unable to read\n");
            return RET_CANNOTREAD;
        }
        dprintf("NT32 done.\n");
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
            return RET_CANNOTREAD;
        }
        dprintf("NT64 done.\n");
        mapping.Seek64(sizeof(IMAGE_NT_HEADERS64));
        return DoNT64(mapping, *nt64);
    }

    eprintf("ERROR: Unknown executable format\n");
    return RET_INVALIDFORMAT;
}

////////////////////////////////////////////////////////////////////////////

INT JustDoIt(const TCHAR *pszFileName)
{
    HANDLE hFile;

#ifdef UNICODE
    dprintf("Opening file '%S'...\n", pszFileName);
#else
    dprintf("Opening file '%s'...\n", pszFileName);
#endif

    hFile = CreateFile(pszFileName, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        eprintf("ERROR: Unable to open file\n");
        return RET_CANNOTOPEN;
    }
    dprintf("Opened.\n");

    INT ret = DoMap(hFile);
    CloseHandle(hFile);
    dprintf("Closed.\n");

    if (ret == 0)
    {
#ifdef UNICODE
        eprintf("'%S' - Done.\n", pszFileName);
#else
        eprintf("'%s' - Done.\n", pszFileName);
#endif
    }

    return ret;
}

BOOL IsDigit(TCHAR ch)
{
    return TEXT('0') <= ch && ch <= TEXT('9');
}

DWORDLONG FileTimeToQuad(const FILETIME *pft)
{
    ULARGE_INTEGER uli;
    uli.LowPart = pft->dwLowDateTime;
    uli.HighPart = pft->dwHighDateTime;
    return uli.QuadPart;
}

DWORDLONG SystemTimeToQuad(const SYSTEMTIME *pst)
{
    FILETIME ft;
    SystemTimeToFileTime(pst, &ft);
    return FileTimeToQuad(&ft);
}

DWORDLONG EpicQuad(void)
{
    SYSTEMTIME st;
    ZeroMemory(&st, sizeof(st));
    st.wYear = 1970;
    st.wMonth = 1;
    st.wDay = 1;
    return SystemTimeToQuad(&st);
}

DWORD QuadToTimeStamp(DWORDLONG quad)
{
    return (DWORD)((quad - EpicQuad()) / 10000000);
}

DWORD SystemTimeToTimeStamp(const SYSTEMTIME *pst)
{
    DWORDLONG quad = SystemTimeToQuad(pst);
    return QuadToTimeStamp(quad);
}

VOID Init(VOID)
{
    g_bIs64Bit = FALSE;
    g_bVerbose = FALSE;
    g_dwTimeStamp = 0;
    g_target = NULL;
}

INT ParseCommandLine(INT argc, TCHAR **targv)
{
    SYSTEMTIME st;
    ZeroMemory(&st, sizeof(st));

    BOOL bSetNow = FALSE, bSetDate = FALSE, bSetTime = FALSE;
    for (int i = 1; i < argc; ++i)
    {
        TCHAR *arg = targv[i];
        if (lstrcmp(arg, TEXT("-v")) == 0)
        {
            g_bVerbose = TRUE;
        }
        else if (lstrcmp(arg, TEXT("-x")) == 0)
        {
            if (i + 1 < argc)
            {
                arg = targv[i + 1];
                ++i;

                TCHAR *endptr;
                DWORD dw = _tcstoul(targv[i + 1], &endptr, 16);
                if (*endptr != 0)
                {
                    eprintf("ERROR: invalid '-x' parameter.\n");
                    return RET_INVALIDARG;
                }
                g_dwTimeStamp = dw;
            }
            else
            {
                eprintf("ERROR: '-x' needs a parameter.\n");
                return RET_INVALIDARG;
            }
        }
        else if (lstrcmp(arg, TEXT("-n")) == 0)
        {
            SYSTEMTIME st;
            GetSystemTime(&st);
            g_dwTimeStamp = SystemTimeToTimeStamp(&st);
            bSetNow = TRUE;
        }
        else if (lstrcmp(arg, TEXT("-d")) == 0)
        {
            // -d YYYYMMDD
            if (i + 1 < argc)
            {
                arg = targv[i + 1];
                ++i;
                if (lstrlen(arg) != 8)
                {
                    eprintf("ERROR: Invalid '-d' parameter.\n");
                    return RET_INVALIDARG;
                }
                for (int k = 0; k < 8; ++k)
                {
                    if (!IsDigit(arg[k]))
                    {
                        eprintf("ERROR: Invalid '-d' parameter.\n");
                        return RET_INVALIDARG;
                    }
                }
                DWORD dw = _tcstoul(arg, NULL, 10);
                st.wDay = WORD(dw % 100);
                st.wMonth = WORD((dw / 100) % 100);
                st.wYear = WORD(dw / 10000);
                bSetDate = TRUE;
            }
            else
            {
                eprintf("ERROR: '-d' needs a parameter.\n");
                return RET_INVALIDARG;
            }
        }
        else if (lstrcmp(arg, TEXT("-t")) == 0)
        {
            // -t HHmmss
            if (i + 1 < argc)
            {
                arg = targv[i + 1];
                ++i;
                if (lstrlen(arg) == 6)
                {
                    for (int k = 0; k < 6; ++k)
                    {
                        if (!IsDigit(arg[k]))
                        {
                            eprintf("ERROR: Invalid '-t' parameter.\n");
                            return RET_INVALIDARG;
                        }
                    }
                    DWORD dw = _tcstoul(arg, NULL, 10);
                    st.wHour = WORD(dw / 10000);
                    st.wMinute = WORD((dw / 100) % 100);
                    st.wSecond = WORD(dw % 100);
                    bSetTime = TRUE;
                }
                else
                {
                    eprintf("ERROR: Invalid '-t' parameter.\n");
                    return RET_INVALIDARG;
                }
            }
            else
            {
                eprintf("ERROR: '-t' needs a parameter.\n");
                return RET_INVALIDARG;
            }
        }
        else if (lstrcmp(arg, TEXT("--help")) == 0)
        {
            return RET_SHOWHELP;
        }
        else if (lstrcmp(arg, TEXT("--version")) == 0)
        {
            return RET_SHOWVERSION;
        }
        else if (arg[0] == TEXT('-'))
        {
            eprintf("ERROR: Invalid argument.\n");
            return RET_INVALIDARG;
        }
        else
        {
            if (g_target)
            {
                eprintf("ERROR: Target must be one.\n");
                return RET_INVALIDARG;
            }
            g_target = arg;
        }
    }

    if (bSetDate || bSetTime)
    {
        if (bSetNow)
        {
            eprintf("ERROR: '-n' and '-d'/'-t' are exclusive.\n");
            return RET_INVALIDARG;
        }
        if (!bSetDate)
        {
            SYSTEMTIME stNow;
            GetSystemTime(&stNow);
            st.wYear = stNow.wYear;
            st.wMonth = stNow.wMonth;
            st.wDay = stNow.wDay;
        }
        g_dwTimeStamp = SystemTimeToTimeStamp(&st);
    }

    if (g_target == NULL)
    {
        eprintf("ERROR: No target specified.\n");
        return RET_INVALIDARG;
    }

    return RET_SUCCESS;
}

extern "C"
INT _tmain(INT argc, TCHAR **targv)
{
    Init();

    INT ret = ParseCommandLine(argc, targv);
    if (ret == RET_INVALIDARG)
    {
        ShowHelp();
        return ret;
    }
    if (ret == RET_SHOWHELP)
    {
        ShowHelp();
        return RET_SUCCESS;
    }
    if (ret == RET_SHOWVERSION)
    {
        ShowVersion();
        return RET_SUCCESS;
    }

    return JustDoIt(g_target);
}

////////////////////////////////////////////////////////////////////////////
