// VirusTotalApi.cpp : 定義 DLL 應用程式的匯出函式。
//

#include "stdafx.h"
#include "VirusTotalApi.h"


// 這是匯出變數的範例
VIRUSTOTALAPI_API int nVirusTotalApi=0;

// 這是匯出函式的範例。
VIRUSTOTALAPI_API int fnVirusTotalApi(void)
{
	return 42;
}

// 這是已匯出的類別建構函式。
// 請參閱 VirusTotalApi.h 中的類別定義
CVirusTotalApi::CVirusTotalApi()
{
	return;
}
