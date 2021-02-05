#pragma once

#include <winsock2.h>
#include <iphlpapi.h>
#include <wbemidl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// <stdint.h>
typedef char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef __int64 int64_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t;

#include "util.h"
#include "crc32.h"
#include "sha1.h"
#include "app.h"

#pragma hdrstop
