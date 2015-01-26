// 下列 ifdef 區塊是建立巨集以協助從 DLL 匯出的標準方式。
// 這個 DLL 中的所有檔案都是使用命令列中所定義 VIRUSTOTALAPI_EXPORTS 符號編譯的。
// 在命令列定義的符號。任何專案都不應定義這個符號
// 這樣一來，原始程式檔中包含這檔案的任何其他專案
// 會將 VIRUSTOTALAPI_API 函式視為從 DLL 匯入的，而這個 DLL 則會將這些符號視為
// 匯出的。
#ifdef VIRUSTOTALAPI_EXPORTS
#define VIRUSTOTALAPI_API __declspec(dllexport)
#else
#define VIRUSTOTALAPI_API __declspec(dllimport)
#endif

// 這個類別是從 VirusTotalApi.dll 匯出的
class VIRUSTOTALAPI_API CVirusTotalApi {
public:
	CVirusTotalApi(void);
	// TODO:  在此加入您的方法。
};

extern VIRUSTOTALAPI_API int nVirusTotalApi;

VIRUSTOTALAPI_API int fnVirusTotalApi(void);
