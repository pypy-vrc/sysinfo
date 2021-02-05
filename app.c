#include "pch.h"

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

typedef LONG NTSTATUS;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK;

typedef struct sysinfo {
    // KUSER_SHARD_DATA
    uint16_t nt_major_version;
    uint16_t nt_minor_version;
    // PEB
    uint16_t os_build_number;
    uint16_t ansi_code_page;
    // CPU
    uint32_t cpu_crc;
    // DISK
    uint8_t disk_hash[20];
    uint32_t volume_ts;
    // SMBIOS
    uint8_t smbios_hash[20];
    uint32_t bios_crc;
    uint32_t memory_crc;
    // IPHLPAPI
    uint8_t net_addr[8];
    uint8_t gateway_addr[8];
} sysinfo_t;

typedef struct smbios {
    char *bios_vendor;
    char *bios_version;
    char *bios_release_date;
    char *system_manufacturer;
    char *system_product_name;
    char *system_version;
    void *system_uuid; // 16 bytes
    char *baseboard_manufacturer;
    char *baseboard_product;
    char *baseboard_serial_number;
    char *processor_manufacturer;
    char *processor_version;
} smbios_t;

__declspec(naked) void __cdecl __cpuid(int *result, int code)
{
    __asm {
        push ebx
        push edi
        mov edi, [esp + 12]
        mov eax, [esp + 16]
        cpuid
        mov [edi], eax
        mov [edi + 4], ebx
        mov [edi + 8], ecx
        mov [edi + 12], edx
        pop edi
        pop ebx
        ret
    }
}

void sysinfo_cpu(sysinfo_t *ctx, uint8_t *b)
{
    uint32_t crc;

    // Processor Brand String
    printf("CPU\n");
    __cpuid((int *)b, 0x80000002);
    dump(b, 16);
    crc = crc32(0, b, 16);
    __cpuid((int *)b, 0x80000003);
    dump(b, 16);
    crc = crc32(crc, b, 16);
    __cpuid((int *)b, 0x80000004);
    dump(b, 16);
    ctx->cpu_crc = crc32(crc, b, 16);
}

void sysinfo_os(sysinfo_t *ctx, uint8_t *b)
{
    uint8_t *p;

    ctx->nt_major_version = *(uint16_t *)0x7FFE026C; // USER_SHARED_DATA->NtMajorVersion
    ctx->nt_minor_version = *(uint16_t *)0x7FFE0270; // USER_SHARED_DATA->NtMinorVersion

    p = (uint8_t *)NtCurrentTeb();
    p = *(uint8_t **)&p[sizeof(p) * 12]; // TEB->PEB
    ctx->os_build_number = *(uint16_t *)&p[0xAC]; // OSBuildNumber

    p = *(void **)&p[0x58]; // AnsiCodePageData
    if (p) {
        ctx->ansi_code_page = *(uint16_t *)&p[2];
    }
}

void sysinfo_storage(sysinfo_t *ctx, sha1_t *sha1, uint8_t *b)
{
    HMODULE m;
    HANDLE file;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iob;
    uint32_t offset;

    m = GetModuleHandleW(L"NTDLL");
    if (m == NULL) {
        return;
    }

    // Device: "\\??\\C:"
    ((int *)b)[0] = 0x3F005C;
    ((int *)b)[1] = 0x5C003F;
    ((int *)b)[2] = 0x3A003F;
    *(short *)&b[8] = *(short *)0x7FFE0030; // USER_SHARED_DATA->NtSystemRoot

    us.Buffer = (void *)b;
    us.MaximumLength = us.Length = 12;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0xC0; // OBJ_CASE_INSENSITIVE(0x40) | OBJ_OPENIF(0x80)
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    if (GetProcAddress(m, "NtOpenFile")(&file, SYNCHRONIZE, &oa, &iob, 0, 0x20 /*FILE_SYNCHRONOUS_IO_NONALERT*/) >= 0) {
        // DISK_GEOMETRY
        if (GetProcAddress(m, "NtDeviceIoControlFile")(file, NULL, NULL, NULL, &iob, 0x70000 /*IOCTL_DISK_GET_DRIVE_GEOMETRY*/, NULL, 0, b, 24) >= 0) {
            printf("Storage:Cylinders={%08x%08x}\n", *(uint32_t *)&b[4], *(uint32_t *)b);
            sha1_update(sha1, b, 24);
        }

        // STORAGE_PROPERTY_QUERY
        ((int *)b)[0] = 0; // PropertyId=StorageDeviceProperty
        ((int *)b)[1] = 0; // QueryType=PropertyStandardQuery
        ((int *)b)[2] = 0; // AdditionalParameters=NULL
        if (GetProcAddress(m, "NtDeviceIoControlFile")(file, NULL, NULL, NULL, &iob, 0x2D1400 /*IOCTL_STORAGE_QUERY_PROPERTY*/, b, 12, b, 4096) >= 0) {
            offset = *(uint32_t *)&b[16]; // ProductIdOffset
            if (offset && offset < 4096) {
                printf("Storage:ProductId={%s}\n", &b[offset]);
                sha1_update(sha1, &b[offset], strlen((char *)&b[offset]));
            }
            offset = *(uint32_t *)&b[24]; // SerialNumberOffset
            if (offset && offset < 4096) {
                printf("Storage:SerialNumber={%s}\n", &b[offset]);
                sha1_update(sha1, &b[offset], strlen((char *)&b[offset]));
            }
        }

        GetProcAddress(m, "NtClose")(file);
    }

    // Directory: "\\??\\C:\\"
    ((int *)b)[0] = 0x3F005C;
    ((int *)b)[1] = 0x5C003F;
    ((int *)b)[2] = 0x3A003F;
    *(short *)&b[8] = *(short *)0x7FFE0030; // USER_SHARED_DATA->NtSystemRoot
    ((int *)b)[3] = 0x5C;

    us.Buffer = (void *)b;
    us.MaximumLength = us.Length = 14;

    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = 0xC0; // OBJ_CASE_INSENSITIVE(0x40) | OBJ_OPENIF(0x80)
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    if (GetProcAddress(m, "NtOpenFile")(&file, SYNCHRONIZE, &oa, &iob, 0, 0x20 /*FILE_SYNCHRONOUS_IO_NONALERT*/) >= 0) {
           // FILE_FS_VOLUME_INFORMATION
        if (GetProcAddress(m, "NtQueryVolumeInformationFile")(file, &iob, b, 256, 1 /*FileFsVolumeInformation*/) >= 0) {
            printf("Storage:VolumeCreationTime={%08x%08x}\n", *(uint32_t *)&b[4], *(uint32_t *)b);
            ctx->volume_ts = (uint32_t)((*(unsigned __int64 *)b - 116444736000000000) / 10000000);
        }
        GetProcAddress(m, "NtClose")(file);
    }
}

void sysinfo_parse_smbios_(sysinfo_t *ctx, smbios_t *smbios, uint8_t *p, char **texts, uint32_t text_count)
{
    uint32_t crc;

    if (p[0] == 127) {
        // End of Table
        return;
    }

    if (p[0] == 0) {
        // BIOS Information
        if (p[1] >= 18) { // 2.0+
            crc = 0;
            if (p[4] && p[4] <= text_count) { // Vendor
                printf("SMBIOS:BIOS Vendor={%s}\n", texts[p[4] - 1]);
                smbios->bios_vendor = texts[p[4] - 1];
                crc = crc32(crc, texts[p[4] - 1], strlen(texts[p[4] - 1]));
            }
            if (p[5] && p[5] <= text_count) { // BIOS Version
                printf("SMBIOS:BIOS Version={%s}\n", texts[p[5] - 1]);
                smbios->bios_version = texts[p[5] - 1];
                crc = crc32(crc, texts[p[5] - 1], strlen(texts[p[5] - 1]));
            }
            if (p[8] && p[8] <= text_count) { // BIOS Release Date
                printf("SMBIOS:BIOS Release Date={%s}\n", texts[p[8] - 1]);
                smbios->bios_release_date = texts[p[8] - 1];
                crc = crc32(crc, texts[p[8] - 1], strlen(texts[p[8] - 1]));
            }
            ctx->bios_crc = crc;
        }
        return;
    }

    if (p[0] == 1) {
        // System Information
           if (p[1] >= 8) { // 2.0+
            if (p[4] && p[4] <= text_count) { // Manufacturer
                smbios->system_manufacturer = texts[p[4] - 1];
            }
            if (p[5] && p[5] <= text_count) { // Product Name
                smbios->system_product_name = texts[p[5] - 1];
            }
            if (p[6] && p[6] <= text_count) { // Version
                smbios->system_version = texts[p[6] - 1];
            }
            if (p[1] >= 25) { // 2.1+
                smbios->system_uuid = &p[8];
            }
        }
        return;
    }

    if (p[0] == 2) {
        // Baseboard Information
        if (p[1] >= 8) { // 2.0+
            if (p[4] && p[4] <= text_count) { // Manufacturer
                smbios->baseboard_manufacturer = texts[p[4] - 1];
            }
            if (p[5] && p[5] <= text_count) { // Product
                smbios->baseboard_product = texts[p[5] - 1];
            }
            if (p[7] && p[7] <= text_count) { // Serial Number
                smbios->baseboard_serial_number = texts[p[7] - 1];
            }
        }
        return;
    }

    if (p[0] == 4) {
        // Processor Information
        if (p[1] >= 25) { // 2.0+
            if (p[7] && p[7] <= text_count) { // Processor Manufacturer
                smbios->processor_manufacturer = texts[p[7] - 1];
            }
            if (p[16] && p[16] <= text_count) { // Processor Version
                smbios->processor_version = texts[p[16] - 1];
            }
        }
        return;
    }

    if (p[0] == 17) {
        // Memory Device
        if (p[1] >= 27 && // 2.3+
            *(uint16_t *)&p[12]) { // Size (0 = no memory device is installed)
            crc = 0;
            if (p[24] && p[24] <= text_count) { // Serial Number
                printf("SMBIOS:Memory Serial Number={%s}\n", texts[p[24] - 1]);
                crc = crc32(crc, texts[p[24] - 1], strlen(texts[p[24] - 1]));
            }
            if (p[26] && p[26] <= text_count) { // Part Number
                printf("SMBIOS:Memory Part Number={%s}\n", texts[p[26] - 1]);
                crc = crc32(crc, texts[p[26] - 1], strlen(texts[p[26] - 1]));
            }
            // �޸𸮴� ������ �ٲ� ���� �� �����ϱ� ���ϱ�
            ctx->memory_crc += crc;
        }
        return;
    }
}

void sysinfo_parse_smbios(sysinfo_t *ctx, const void *buf, size_t len)
{
    uint8_t *p, *end, *data;
    uint32_t text_count;
    char *texts[16];
    smbios_t smbios;
    sha1_t sha1;

    memset(&smbios, 0, sizeof(smbios));

    p = (uint8_t *)buf,
    end = p + len;

    while (&p[3] < end && p[1] >= 4) {
        data = p;
        p += p[1];

        texts[0] = (char *)p;
        text_count = 1;

        for (;;) {
            p += strlen((char *)p) + 1;
            if (*p == 0) {
                ++p;
                break;
            }
            if (text_count < ARRAYSIZE(texts)) {
                texts[text_count] = (char *)p;
                ++text_count;
            }
        }

        sysinfo_parse_smbios_(ctx, &smbios, data, texts, text_count);
    }

    sha1_init(&sha1);
    if (smbios.system_manufacturer) {
        printf("SMBIOS:System Manufacturer={%s}\n", smbios.system_manufacturer);
        sha1_update(&sha1, smbios.system_manufacturer, strlen(smbios.system_manufacturer));
    }
    if (smbios.system_product_name) {
        printf("SMBIOS:System Product Name={%s}\n", smbios.system_product_name);
        sha1_update(&sha1, smbios.system_product_name, strlen(smbios.system_product_name));
    }
    if (smbios.system_version) {
        printf("SMBIOS:System Version={%s}\n", smbios.system_version);
        sha1_update(&sha1, smbios.system_version, strlen(smbios.system_version));
    }
    if (smbios.system_uuid) {
        printf("SMBIOS:System UUID\n");
        dump(smbios.system_uuid, 16);
        sha1_update(&sha1, smbios.system_uuid, 16);
    }
    if (smbios.baseboard_manufacturer) {
        printf("SMBIOS:Baseboard Manufacturer={%s}\n", smbios.baseboard_manufacturer);
        sha1_update(&sha1, smbios.baseboard_manufacturer, strlen(smbios.baseboard_manufacturer));
    }
    if (smbios.baseboard_product) {
        printf("SMBIOS:Baseboard Product={%s}\n", smbios.baseboard_product);
        sha1_update(&sha1, smbios.baseboard_product, strlen(smbios.baseboard_product));
    }
    if (smbios.baseboard_serial_number) {
        printf("SMBIOS:Baseboard Serial Number={%s}\n", smbios.baseboard_serial_number);
        sha1_update(&sha1, smbios.baseboard_serial_number, strlen(smbios.baseboard_serial_number));
    }
    if (smbios.processor_manufacturer) {
        printf("SMBIOS:Processor Manufacturer={%s}\n", smbios.processor_manufacturer);
        sha1_update(&sha1, smbios.processor_manufacturer, strlen(smbios.processor_manufacturer));
    }
    if (smbios.processor_version) {
        printf("SMBIOS:Processor Version={%s}\n", smbios.processor_version);
        sha1_update(&sha1, smbios.processor_version, strlen(smbios.processor_version));
    }
    sha1_final(&sha1, ctx->smbios_hash);
}

void sysinfo_smbios(sysinfo_t *ctx, uint8_t *b)
{
    HMODULE m;
    BSTR strNetworkResource, strClass;
    IWbemLocator *locator;
    IWbemServices *services;
    IEnumWbemClassObject *enumerator;
    ULONG objects;
    IWbemClassObject *object;
    VARIANT v;

    m = GetModuleHandleW(L"NTDLL");
    if (m == NULL) {
        return;
    }

    // SYSTEM_FIRMWARE_TABLE_INFORMATION
    ((int *)b)[0] = 'RSMB'; // ProviderSignature
    ((int *)b)[1] = 1; // Action = SystemFirmwareTableGet
    ((int *)b)[2] = 0; // TableID
    ((int *)b)[3] = 65536 - 16; // TableBufferLength
    
    if (GetProcAddress(m, "NtQuerySystemInformation")(76 /*SystemFirmwareTableInformation*/, b, 65536, b) >= 0) {
        sysinfo_parse_smbios(ctx, &b[24], *(uint32_t *)&b[20]); // TableBuffer, TableBufferLength
        return;
    }

    // Get SMBIOS from WMI (for XP, 2003)    
    m = GetModuleHandleW(L"OLE32");
    if (m == NULL ||
        GetProcAddress(m, "CoInitializeEx")(NULL, COINIT_APARTMENTTHREADED) != S_OK) {
        return;
    }

    strNetworkResource = SysAllocString(L"ROOT\\WMI");
    strClass = SysAllocString(L"MSSmBios_RawSMBiosTables");

    // CLSID_WbemLocator
    ((int *)b)[0] = 0x4590F811;
    ((int *)b)[1] = 0x11D01D3A;
    ((int *)b)[2] = 0xAA001F89;
    ((int *)b)[3] = 0x242E4B00;

    // IID_IWbemLocator
    ((int *)b)[4] = 0xDC12A687;
    ((int *)b)[5] = 0x11CF737F;
    ((int *)b)[6] = 0xAA004D88;
    ((int *)b)[7] = 0x242E4B00;

    if (GetProcAddress(m, "CoInitializeSecurity")(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0 /*EOAC_NONE*/, NULL) == S_OK &&
        CoCreateInstance((IID *)b, NULL, CLSCTX_INPROC_SERVER, (IID *)&b[16], &locator) == S_OK) {
        if (locator->lpVtbl->ConnectServer(locator, strNetworkResource, NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &services) == S_OK) {
            if (services->lpVtbl->CreateInstanceEnum(services, strClass, WBEM_FLAG_FORWARD_ONLY, NULL, &enumerator) == S_OK) {
                VariantInit(&v);
                while (enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1, &object, &objects) == S_OK) {
                    if (object->lpVtbl->Get(object, L"SMBiosData", 0, &v, NULL, NULL) == S_OK) {
                        if (v.vt == (VT_ARRAY | VT_UI1) &&
                            v.parray->cDims &&
                            v.parray->rgsabound[0].cElements) {
                            sysinfo_parse_smbios(ctx, v.parray->pvData, v.parray->rgsabound[0].cElements);
                        }
                        VariantClear(&v);
                    }
                    object->lpVtbl->Release(object);
                }
                enumerator->lpVtbl->Release(enumerator);
            }
            services->lpVtbl->Release(services);
        }
        locator->lpVtbl->Release(locator);
    }

    SysFreeString(strClass);
    SysFreeString(strNetworkResource);
    GetProcAddress(m, "CoUninitialize")();
}

void sysinfo_mac(sysinfo_t *ctx, uint8_t *b)
{
    HMODULE m;
    DWORD i, addr, index;
    MIB_IPFORWARDROW *fw_row;
    MIB_IFROW *if_row;
    MIB_IPNETTABLE *ip_table;
    MIB_IPNETROW *ip_row;
    
    m = LoadLibraryW(L"IPHLPAPI");
    if (m == NULL) {
        return;
    }

    fw_row = (MIB_IPFORWARDROW *)b;
    if (GetProcAddress(m, "GetBestRoute")(0, 0, fw_row) == NO_ERROR) {
        addr = fw_row->dwForwardNextHop;
        index = fw_row->dwForwardIfIndex;
        if_row = (MIB_IFROW *)b;
        if_row->dwIndex = index;
        if (GetProcAddress(m, "GetIfEntry")(if_row) == NO_ERROR) {
            memcpy(ctx->net_addr, if_row->bPhysAddr, if_row->dwPhysAddrLen);
            *(ULONG *)b = 65536 - 4;
            ip_table = (MIB_IPNETTABLE *)&b[4];
            if (GetProcAddress(m, "GetIpNetTable")(ip_table, b, FALSE) == NO_ERROR) {
                ip_row = ip_table->table;
                for (i = ip_table->dwNumEntries; i; ++ip_row, --i) {
                    if (ip_row->dwIndex == index &&
                        ip_row->dwAddr == addr) {
                        memcpy(ctx->gateway_addr, ip_row->bPhysAddr, ip_row->dwPhysAddrLen);
                        break;
                    }
                }
            }
        }
    }

    FreeLibrary(m);
}

// Retrieves System Info
void sysinfo_resolve(sysinfo_t *ctx)
{
    uint8_t *b;
    sha1_t sha1;

    memset(ctx, 0,sizeof(*ctx));

    b = malloc(65536);
    if (b == NULL) {
        return;
    }

    sysinfo_cpu(ctx, b);
    sysinfo_os(ctx, b);

    sha1_init(&sha1);
    sysinfo_storage(ctx, &sha1, b);
    sha1_final(&sha1, ctx->disk_hash);

    sysinfo_smbios(ctx, b);
    sysinfo_mac(ctx, b);

    free(b);
}

#if 0
/*__declspec(noinline)*/ BOOL pe_checksum(HMODULE m)
{
    BOOL result = FALSE;
    const uint8_t *p = (uint8_t *)NtCurrentTeb();
    p = *(uint8_t **)&p[sizeof(p) * 12]; // TEB->PEB
    p = *(uint8_t **)&p[sizeof(p) * 3]; // PEB->PEB_LDR_DATA
    p = *(uint8_t **)&p[sizeof(p) * 3 + 8]; // PEB_LDR_DATA->InMemoryOrderModuleList.FLink
    if (m)
        while (*(HMODULE *)&p[sizeof(p) * 4] != m) // LDR_MODULE->BaseAddress
            p = *(uint8_t **)p; // InMemoryOrderModuleList.FLink
    else
        m = *(HMODULE *)&p[sizeof(p) * 4];
    {
        HANDLE file = CreateFileW(*(const wchar_t **)&p[sizeof(void *) * 8], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            DWORD size = GetFileSize(file, NULL);
            if (size && size != INVALID_FILE_SIZE) {
                HANDLE mapping = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
                if (mapping) {
                    LPVOID base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
                    if (base) {
                        DWORD i = 0;
                        WORD *ptr = base,
                            *end_ptr = &ptr[size >> 1];
                        while (ptr < end_ptr) {
                            i += *ptr++;
                            i = (i >> 16) + (WORD)i;
                        }
                        i = (WORD)(i + (i >> 16));
                        {
                            DWORD j = ((IMAGE_NT_HEADERS *)((char *)m + ((IMAGE_DOS_HEADER *)m)->e_lfanew))->OptionalHeader.CheckSum;
                            i = (WORD)(i - (i < (WORD)j));
                            i = (WORD)(i - (WORD)j);
                            i = (WORD)(i - (i < (j >> 16)));
                            i = (WORD)(i - (j >> 16));
                            result = size == j - i;
                        }
                        UnmapViewOfFile(base);
                    }
                    CloseHandle(mapping);
                }
            }
            CloseHandle(file);
        }
    }
    return result;
}
#endif

int app_main(int argc, const char **argv)
{
    sysinfo_t sysinfo;

    sysinfo_resolve(&sysinfo);

    // OS

    printf("OS=%u.%u.%u;%u\n",
        sysinfo.nt_major_version,
        sysinfo.nt_minor_version,
        sysinfo.os_build_number,
        sysinfo.ansi_code_page);

    // CPU

    printf("%s=%08x\n", "CPU", sysinfo.cpu_crc);

    // STORAGE

    printf("DISK HASH\n");
    dump(sysinfo.disk_hash, sizeof(sysinfo.disk_hash));

    printf("%s=%08x\n", "Volume", sysinfo.volume_ts);

    // SMBIOS

    printf("SMBIOS HASH\n");
    dump(sysinfo.smbios_hash, sizeof(sysinfo.smbios_hash));

    printf("%s=%08x\n", "BIOS", sysinfo.bios_crc);
    printf("%s=%08x\n", "Memory", sysinfo.memory_crc);

    // NETWORK

    printf("Net\n");
    dump(sysinfo.net_addr, sizeof(sysinfo.net_addr));

    printf("Gateway\n");
    dump(sysinfo.gateway_addr, sizeof(sysinfo.gateway_addr));

    system("pause");
    return 0;
}
