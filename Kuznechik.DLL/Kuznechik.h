#pragma once

#include <cstdint>

#ifdef KUZNECHIK_EXPORTS
#define KUZNECHIK_API __declspec(dllexport)
#else
#define KUZNECHIK_API __declspec(dllimport)
#endif

extern "C" {
    KUZNECHIK_API void InitKey(const uint8_t* key);
    KUZNECHIK_API void EncryptBlock(const uint8_t* input, uint8_t* output);
    KUZNECHIK_API void DecryptBlock(const uint8_t* input, uint8_t* output);
}