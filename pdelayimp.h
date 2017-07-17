// pdelayimp.cpp --- portable <delayimp.h>
// Copyright (C) 2017 Katayama Hirofumi MZ.
// This software is public domain software (PDS).
////////////////////////////////////////////////////////////////////////////

#ifndef PDELAYIMP_H
#define PDELAYIMP_H     1

typedef DWORD RVA;

typedef struct ImgDelayDescr {
    DWORD   grAttrs;
    RVA     rvaDLLName;
    RVA     rvaHmod;
    RVA     rvaIAT;
    RVA     rvaINT;
    RVA     rvaBoundIAT;
    RVA     rvaUnloadIAT;
    DWORD   dwTimeStamp;
} ImgDelayDescr, *PImgDelayDescr;

#endif  /* ndef PDELAYIMP_H */
