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

////////////////////////////////////////////////////////////////////////////

static BOOL   g_bIs64Bit            = FALSE;
static BOOL   g_bVerbose            = FALSE;
static DWORD  g_dwTimeStamp         = 0;
static TCHAR *g_pszTargetFile       = NULL;

static void InitApp(void)
{
    g_bIs64Bit = FALSE;
    g_bVerbose = FALSE;
    g_dwTimeStamp = 0;
    g_pszTargetFile = NULL;
}

static void ShowVersion(void)
{
    puts("ExeTimeStampKiller Version 0.9.3 / 2017.07.19\n"
         "Written by Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>.\n"
         "This software is public domain software (PDS).\n");
}

static void ShowHelp(void)
{
    puts("Usage: ExeTimeStampKiller [options] file.exe\n"
         "\nOptions:\n"
         "-n              Set now.\n"
         "-d YYYYMMDD     Set date.\n"
         "-t HHmmss       Set time.\n"
         "-v              Verbose output.\n"
         "-g              Parse as global time.\n"
         "-x XXXXXXXX     Set hexidemical timestamp value to set.\n"
         "--help          Show this help.\n"
         "--version       Show version.\n");
}

////////////////////////////////////////////////////////////////////////////

static inline void eprintf(const char *fmt, ...)
{
    char buf[1024];

    va_list va;
    va_start(va, fmt);
    wvsprintfA(buf, fmt, va);
    va_end(va);

    fputs(buf, stderr);
    fflush(stderr);
}

static inline void dprintf(const char *fmt, ...)
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

enum RETURN_CODE
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

static INT
DoSym(MFileMapping& mapping, DWORD PointerToSymbolTable, DWORD NumberOfSymbols)
{
    if (NumberOfSymbols == 0 || PointerToSymbolTable == 0)
        return RET_SUCCESS;

    DWORD offset = PointerToSymbolTable;

    DWORD size = NumberOfSymbols * sizeof(IMAGE_SYMBOL);
    mapping.SetPos64(offset);
    MTypedMapView<IMAGE_SYMBOL> symbols = mapping.GetTypedData<IMAGE_SYMBOL>(size);
    if (!symbols)
    {
        eprintf("ERROR: Unable to read\n");
        return RET_CANNOTREAD;
    }

    DWORD StorageClass = IMAGE_SYM_CLASS_NULL;
    DWORD NumberOfAuxSymbols = 0;
    for (DWORD i = 0; i < NumberOfSymbols; ++i)
    {
        if (NumberOfAuxSymbols)
        {
            IMAGE_AUX_SYMBOL& aux = (IMAGE_AUX_SYMBOL&)symbols[i];

            dprintf("[IMAGE_AUX_SYMBOL #%lu @ 0x%08lX]\n", i, offset);

            if (StorageClass == IMAGE_SYM_CLASS_SECTION)
            {
                // FUCK
                aux.Section.CheckSum = 0;
            }

            --NumberOfAuxSymbols;
        }
        else
        {
            dprintf("[IMAGE_SYMBOL #%lu @ 0x%08lX]\n", i, offset);
            dprintf("Value: 0x%08lX\n", symbols[i].Value);
            dprintf("SectionNumber: 0x%04X\n", symbols[i].SectionNumber);
            dprintf("Type: 0x%04X\n", symbols[i].Type);
            dprintf("StorageClass: 0x%02X\n", symbols[i].StorageClass);
            dprintf("NumberOfAuxSymbols: 0x%02X\n", symbols[i].NumberOfAuxSymbols);

            StorageClass = symbols[i].StorageClass;
            NumberOfAuxSymbols = symbols[i].NumberOfAuxSymbols;
        }
        offset += sizeof(IMAGE_SYMBOL);
    }

    return RET_SUCCESS;
}

static INT
DoFileHeader(MFileMapping& mapping, IMAGE_FILE_HEADER& file, DWORD offset)
{
    dprintf("[IMAGE_FILE_HEADER @ 0x%08lX]\n", offset);
    dprintf("Machine: 0x%04X\n", file.Machine);
    dprintf("NumberOfSections: 0x%04X\n", file.NumberOfSections);
    dprintf("TimeDateStamp: 0x%08lX\n", file.TimeDateStamp);
    dprintf("PointerToSymbolTable: 0x%08lX\n", file.PointerToSymbolTable);
    dprintf("NumberOfSymbols: 0x%08lX\n", file.NumberOfSymbols);
    dprintf("SizeOfOptionalHeader: 0x%04X\n", file.SizeOfOptionalHeader);
    dprintf("Characteristics: 0x%04X\n", file.Characteristics);

    // FUCK
    file.TimeDateStamp = g_dwTimeStamp;

    DWORD PointerToSymbolTable = file.PointerToSymbolTable;
    DWORD NumberOfSymbols = file.NumberOfSymbols;
    if (NumberOfSymbols)
    {
        INT ret = DoSym(mapping, PointerToSymbolTable, NumberOfSymbols);
        if (ret)
            return ret;
    }

    return RET_SUCCESS;
}

static INT
DoExp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    MTypedMapView<IMAGE_EXPORT_DIRECTORY> exp;
    mapping.SetPos64(offset);
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

    // FUCK
    exp->TimeDateStamp = g_dwTimeStamp;
    return RET_SUCCESS;
}

static INT
DoImp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.SetPos64(offset);
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

        // FUCK
        // NOTE: We should not change import section.
        //desc->TimeDateStamp = g_dwTimeStamp;

        if (desc->Characteristics == 0)
            break;

        mapping.Seek64(sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    return RET_SUCCESS;
}

static INT
DoResDir(MFileMapping& mapping, SECTION_INFO& sec_info,
         DWORD res_offset, IMAGE_RESOURCE_DIRECTORY& dir, DWORD pos);

static INT
DoResEnt(MFileMapping& mapping, SECTION_INFO& sec_info,
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
        mapping.SetPos64(pos);

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

        mapping.SetPos64(res_offset + ent.OffsetToData);

        MTypedMapView<IMAGE_RESOURCE_DATA_ENTRY> data;
        data = mapping.GetTypedData<IMAGE_RESOURCE_DATA_ENTRY>();
        if (!data)
        {
            eprintf("ERROR: Unable to read\n");
            return RET_CANNOTREAD;
        }

        return RET_SUCCESS;
    }
}

static INT
DoResDir(MFileMapping& mapping, SECTION_INFO& sec_info,
         DWORD res_offset, IMAGE_RESOURCE_DIRECTORY& dir, DWORD pos)
{
    dprintf("[IMAGE_RESOURCE_DIRECTORY @ 0x%08lX]\n", pos);
    dprintf("Characteristics: 0x%08lX\n", dir.Characteristics);
    dprintf("TimeDateStamp: 0x%08lX\n", dir.TimeDateStamp);
    dprintf("MajorVersion: 0x%04X\n", dir.MajorVersion);
    dprintf("MinorVersion: 0x%04X\n", dir.MinorVersion);
    dprintf("NumberOfNamedEntries: 0x%04X\n", dir.NumberOfNamedEntries);
    dprintf("NumberOfIdEntries: 0x%04X\n", dir.NumberOfIdEntries);

    // FUCK
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

static INT
DoRes(MFileMapping& mapping, SECTION_INFO& sec_info, DWORD offset, DWORD size)
{
    mapping.SetPos64(offset);

    MTypedMapView<IMAGE_RESOURCE_DIRECTORY> dir;
    dir = mapping.GetTypedData<IMAGE_RESOURCE_DIRECTORY>();
    if (!dir)
    {
        eprintf("ERROR: Unable to read\n");
        return RET_CANNOTREAD;
    }

    return DoResDir(mapping, sec_info, offset, *dir, offset);
}

static INT
DoLoadConfig32(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.SetPos64(offset);

    MTypedMapView<IMAGE_LOAD_CONFIG_DIRECTORY32> config;
    config = mapping.GetTypedData<IMAGE_LOAD_CONFIG_DIRECTORY32>();
    if (!config)
    {
        eprintf("ERROR: Unable to read\n");
        return RET_CANNOTREAD;
    }

    // FUCK
    config->TimeDateStamp = g_dwTimeStamp;
    return RET_SUCCESS;
}

static INT
DoLoadConfig64(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.SetPos64(offset);

    MTypedMapView<IMAGE_LOAD_CONFIG_DIRECTORY64> config;
    config = mapping.GetTypedData<IMAGE_LOAD_CONFIG_DIRECTORY64>();
    if (!config)
    {
        eprintf("ERROR: Unable to read\n");
        return RET_CANNOTREAD;
    }

    // FUCK
    config->TimeDateStamp = g_dwTimeStamp;
    return RET_SUCCESS;
}

static INT
DoLoadConfig(MFileMapping& mapping, DWORD offset, DWORD size)
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

static INT
DoDebug(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.SetPos64(offset);

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
        dprintf("[IMAGE_DEBUG_DIRECTORY #%lu @ 0xs%08lX]\n", i, offset);
        dprintf("Characteristics: 0x%08lX\n", debug[i].Characteristics);
        dprintf("TimeDateStamp: 0x%08lX\n", debug[i].TimeDateStamp);
        dprintf("MajorVersion: 0x%04X\n", debug[i].MajorVersion);
        dprintf("MinorVersion: 0x%04X\n", debug[i].MinorVersion);
        dprintf("Type: 0x%08lX\n", debug[i].Type);
        dprintf("SizeOfData: 0x%08lX\n", debug[i].SizeOfData);
        dprintf("AddressOfRawData: 0x%08lX\n", debug[i].AddressOfRawData);
        dprintf("PointerToRawData: 0x%08lX\n", debug[i].PointerToRawData);

        // FUCK
        debug[i].TimeDateStamp = g_dwTimeStamp;

        offset += sizeof(IMAGE_DEBUG_DIRECTORY);
    }

    return RET_SUCCESS;
}

static INT
DoBoundImp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    MTypedMapView<IMAGE_BOUND_IMPORT_DESCRIPTOR> desc;
    MTypedMapView<IMAGE_BOUND_FORWARDER_REF> ref;

    DWORDLONG pos = offset;
    for (;;)
    {
        if (offset + size < pos + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR))
            break;

        mapping.SetPos64(pos);
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

        // FUCK
        // NOTE: We should not change bound import section.
        //desc->TimeDateStamp = g_dwTimeStamp;

        pos += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);

        DWORD count = desc->NumberOfModuleForwarderRefs;
        DWORD ref_size = count * sizeof(IMAGE_BOUND_FORWARDER_REF);
        if (offset + size < pos + ref_size)
            break;

        mapping.SetPos64(pos);
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

            // FUCK
            // NOTE: We should not change bound import section.
            //ref[i].TimeDateStamp = g_dwTimeStamp;

            pos += sizeof(IMAGE_BOUND_FORWARDER_REF);
        }
    }

    return RET_SUCCESS;
}

static INT
DoDelayImp(MFileMapping& mapping, DWORD offset, DWORD size)
{
    mapping.SetPos64(offset);

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

static INT
DoSect(MFileMapping& mapping, SECTION_INFO& sec_info,
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

static INT
DoNT32(MFileMapping& mapping, IMAGE_NT_HEADERS32& nt32, DWORD nt_offset)
{
    IMAGE_OPTIONAL_HEADER32& opt32 = nt32.OptionalHeader;
    if (opt32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        eprintf("ERROR: Invalid executable file\n");
        return RET_INVALIDFORMAT;
    }

    DWORD file_header_offset = nt_offset + sizeof(DWORD);
    DWORD opt_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
    dprintf("[IMAGE_OPTIONAL_HEADER32 @ 0x%08lX]\n", opt_offset);
    dprintf("ImageBase: 0x%08lX\n", opt32.ImageBase);
    dprintf("SizeOfHeaders: 0x%08lX\n", opt32.SizeOfHeaders);
    dprintf("CheckSum: 0x%08lX\n", opt32.CheckSum);
    dprintf("Subsystem: 0x%04X\n", opt32.Subsystem);
    dprintf("DllCharacteristics: 0x%04X\n", opt32.DllCharacteristics);

    // FUCK
    opt32.CheckSum = 0;

    IMAGE_FILE_HEADER& file = nt32.FileHeader;
    WORD NumberOfSections = file.NumberOfSections;
    dprintf("NumberOfSections: 0x%04X\n", NumberOfSections);
    INT ret = DoFileHeader(mapping, file, file_header_offset);
    if (ret)
        return ret;

    MTypedMapView<IMAGE_SECTION_HEADER> sections;
    dprintf("[IMAGE_SECTION_HEADER @ 0x%08lX]\n", mapping.GetPos());
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

static INT
DoNT64(MFileMapping& mapping, IMAGE_NT_HEADERS64& nt64, DWORD nt_offset)
{
    IMAGE_OPTIONAL_HEADER64& opt64 = nt64.OptionalHeader;
    if (opt64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        eprintf("ERROR: Invalid executable file\n");
        return RET_INVALIDFORMAT;
    }

    DWORD file_header_offset = nt_offset + sizeof(DWORD);
    DWORD opt_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
    dprintf("[IMAGE_OPTIONAL_HEADER64 @ 0x%08lX]\n", opt_offset);
    dprintf("ImageBase: 0x%08lX%08lX\n", HILONG(opt64.ImageBase),
                                         LOLONG(opt64.ImageBase));
    dprintf("SizeOfHeaders: 0x%08lX\n", opt64.SizeOfHeaders);
    dprintf("CheckSum: 0x%08lX\n", opt64.CheckSum);
    dprintf("Subsystem: 0x%04X\n", opt64.Subsystem);
    dprintf("DllCharacteristics: 0x%04X\n", opt64.DllCharacteristics);

    // FUCK
    opt64.CheckSum = 0;

    IMAGE_FILE_HEADER& file = nt64.FileHeader;
    WORD NumberOfSections = file.NumberOfSections;
    dprintf("NumberOfSections: 0x%04X\n", NumberOfSections);
    INT ret = DoFileHeader(mapping, file, file_header_offset);
    if (ret)
        return ret;

    MTypedMapView<IMAGE_SECTION_HEADER> sections;
    dprintf("[IMAGE_SECTION_HEADER @ 0x%08lX]\n", mapping.GetPos());
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

static INT DoMap(HANDLE hFile)
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
            dprintf("[IMAGE_DOS_HEADER @ 0x%08lX]\n", 0L);
            dprintf("e_csum: 0x%04X\n", dos->e_csum);
            dprintf("e_lfanew: 0x%08lX\n", dos->e_lfanew);

            // FUCK
            dos->e_csum = 0;

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

    DWORD offset = mapping.GetPos();
    if (SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        g_bIs64Bit = FALSE;
        dprintf("[IMAGE_NT_HEADERS32 @ 0x%08lX]\n", offset);

        MTypedMapView<IMAGE_NT_HEADERS32> nt32;
        nt32 = mapping.GetTypedData<IMAGE_NT_HEADERS32>();
        if (!nt32)
        {
            eprintf("ERROR: Unable to read\n");
            return RET_CANNOTREAD;
        }

        dprintf("NT32 done.\n");
        mapping.Seek64(sizeof(IMAGE_NT_HEADERS32));

        return DoNT32(mapping, *nt32, offset);
    }
    else if (SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        g_bIs64Bit = TRUE;
        dprintf("[IMAGE_NT_HEADERS64 @ 0x%08lX]\n", offset);

        MTypedMapView<IMAGE_NT_HEADERS64> nt64;
        nt64 = mapping.GetTypedData<IMAGE_NT_HEADERS64>();
        if (!nt64)
        {
            eprintf("ERROR: Unable to read\n");
            return RET_CANNOTREAD;
        }
        dprintf("NT64 done.\n");
        mapping.Seek64(sizeof(IMAGE_NT_HEADERS64));

        return DoNT64(mapping, *nt64, offset);
    }

    eprintf("ERROR: Unknown executable format\n");
    return RET_INVALIDFORMAT;
}

////////////////////////////////////////////////////////////////////////////

static INT JustDoIt(const TCHAR *pszFileName)
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
#ifdef UNICODE
        eprintf("ERROR: Unable to open file - '%S'\n", pszFileName);
#else
        eprintf("ERROR: Unable to open file - '%s'\n", pszFileName);
#endif
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

static inline BOOL IsDigit(TCHAR ch)
{
    return TEXT('0') <= ch && ch <= TEXT('9');
}

static inline DWORDLONG FileTimeToQuad(const FILETIME *pft)
{
    ULARGE_INTEGER uli;
    uli.LowPart = pft->dwLowDateTime;
    uli.HighPart = pft->dwHighDateTime;
    return uli.QuadPart;
}

static inline DWORDLONG SystemTimeToQuad(const SYSTEMTIME *pst)
{
    FILETIME ft;
    SystemTimeToFileTime(pst, &ft);
    return FileTimeToQuad(&ft);
}

static inline DWORDLONG LocalTimeToQuad(const SYSTEMTIME *pst)
{
    FILETIME ft, ftLocal;
    SystemTimeToFileTime(pst, &ft);
    LocalFileTimeToFileTime(&ft, &ftLocal);
    return FileTimeToQuad(&ftLocal);
}

static inline DWORDLONG EpicQuad(void)
{
    SYSTEMTIME st;
    ZeroMemory(&st, sizeof(st));
    st.wYear = 1970;
    st.wMonth = 1;
    st.wDay = 1;
    return SystemTimeToQuad(&st);
}

static inline DWORD QuadToTimeStamp(DWORDLONG quad)
{
    return (DWORD)((quad - EpicQuad()) / 10000000);
}

static inline DWORD
SystemTimeToTimeStamp(const SYSTEMTIME *pst, BOOL bGlobal)
{
    DWORDLONG quad;
    if (bGlobal)
        quad = SystemTimeToQuad(pst);
    else
        quad = LocalTimeToQuad(pst);
    return QuadToTimeStamp(quad);
}

static INT ParseCommandLine(INT argc, TCHAR **targv)
{
    SYSTEMTIME st;
    ZeroMemory(&st, sizeof(st));

    BOOL bSetNow = FALSE, bSetDate = FALSE, bSetTime = FALSE;
    BOOL bSetHex = FALSE, bGlobal = FALSE;
    for (int i = 1; i < argc; ++i)
    {
        TCHAR *arg = targv[i];
        if (lstrcmp(arg, TEXT("-v")) == 0)
        {
            // -v
            g_bVerbose = TRUE;
        }
        else if (lstrcmp(arg, TEXT("-x")) == 0)
        {
            // -x XXXXXXXX
            if (i + 1 < argc)
            {
                bSetHex = TRUE;
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
            // -n
            GetSystemTime(&st);
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
        else if (lstrcmp(arg, TEXT("-g")) == 0)
        {
            // -g
            bGlobal = TRUE;
        }
        else if (lstrcmp(arg, TEXT("--help")) == 0)
        {
            // --help
            return RET_SHOWHELP;
        }
        else if (lstrcmp(arg, TEXT("--version")) == 0)
        {
            // --version
            return RET_SHOWVERSION;
        }
        else if (arg[0] == TEXT('-') || arg[0] == TEXT('/'))
        {
#ifdef UNICODE
            eprintf("ERROR: Invalid argument - '%S'.\n", arg);
#else
            eprintf("ERROR: Invalid argument - '%s'.\n", arg);
#endif
            return RET_INVALIDARG;
        }
        else
        {
            // file.exe
            if (g_pszTargetFile)
            {
                eprintf("ERROR: Target must be one.\n");
                return RET_INVALIDARG;
            }
            g_pszTargetFile = arg;
        }
    }

    if ((bSetDate || bSetTime || bSetHex) && bSetNow)
    {
        if (bSetDate)
            eprintf("ERROR: '-n' and '-d' are exclusive.\n");
        else if (bSetTime)
            eprintf("ERROR: '-n' and '-t' are exclusive.\n");
        else if (bSetHex)
            eprintf("ERROR: '-n' and '-x' are exclusive.\n");
        return RET_INVALIDARG;
    }

    if (!bSetDate && bSetTime)
    {
        SYSTEMTIME stNow;
        GetSystemTime(&stNow);
        st.wYear = stNow.wYear;
        st.wMonth = stNow.wMonth;
        st.wDay = stNow.wDay;
    }

    if (bSetDate || bSetTime || bSetNow)
    {
        g_dwTimeStamp = SystemTimeToTimeStamp(&st, bGlobal);
    }

    if (g_pszTargetFile == NULL)
    {
        eprintf("ERROR: No target specified.\n");
        return RET_INVALIDARG;
    }

    return RET_SUCCESS;
}

extern "C"
INT _tmain(INT argc, TCHAR **targv)
{
    InitApp();

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

    return JustDoIt(g_pszTargetFile);
}

////////////////////////////////////////////////////////////////////////////
