// MyDiskInfo.cpp: implementation of the CMyDiskInfo class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "MyDiskInfo.h"
#include "windows.h"
#include "winioctl.h"
#include <atlstr.h>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif

const WORD IDE_ATAPI_IDENTIFY = 0xA1;   // 读取ATAPI设备的命令
const WORD IDE_ATA_IDENTIFY   = 0xEC;   // 读取ATA设备的命令

#define _WIN32_WINNT 0x0400


#include "NTDDSCSI.h"
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CMyDiskInfo::CMyDiskInfo()
{

}

CMyDiskInfo::~CMyDiskInfo()
{

}

BOOL __fastcall DoIdentify( HANDLE hPhysicalDriveIOCTL, 
							PSENDCMDINPARAMS pSCIP,
							PSENDCMDOUTPARAMS pSCOP, 
							BYTE btIDCmd, 
							BYTE btDriveNum,
							PDWORD pdwBytesReturned)
{
    pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE;
    pSCIP->irDriveRegs.bFeaturesReg = 0;
    pSCIP->irDriveRegs.bSectorCountReg  = 1;
    pSCIP->irDriveRegs.bSectorNumberReg = 1;
    pSCIP->irDriveRegs.bCylLowReg  = 0;
    pSCIP->irDriveRegs.bCylHighReg = 0;

    pSCIP->irDriveRegs.bDriveHeadReg = (btDriveNum & 1) ? 0xB0 : 0xA0;
    pSCIP->irDriveRegs.bCommandReg = btIDCmd;
    pSCIP->bDriveNumber = btDriveNum;
    pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE;

    return DeviceIoControl(	hPhysicalDriveIOCTL, 
							SMART_RCV_DRIVE_DATA,
							(LPVOID)pSCIP,
							sizeof(SENDCMDINPARAMS) - 1,
							(LPVOID)pSCOP,
							sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE - 1,
							pdwBytesReturned, NULL);
}

char *__fastcall ConvertToString(DWORD dwDiskData[256], int nFirstIndex, int nLastIndex)
{
	static char szResBuf[1024];
	char ss[256];
	int nIndex = 0;
	int nPosition = 0;

	for(nIndex = nFirstIndex; nIndex <= nLastIndex; nIndex++)
	{
		ss[nPosition] = (char)(dwDiskData[nIndex] / 256);
		nPosition++;

		// Get low BYTE for 2nd character
		ss[nPosition] = (char)(dwDiskData[nIndex] % 256);
		nPosition++;
	}

	// End the string
	ss[nPosition] = '\0';

	int i, index=0;
	for(i=0; i<nPosition; i++)
	{
		if(ss[i]==0 || ss[i]==32)	continue;
		szResBuf[index]=ss[i];
		index++;
	}
	szResBuf[index]=0;

	return szResBuf;
}


//// IOCTL_STORAGE_GET_MEDIA_TYPES_EX可能返回不止一条DEVICE_MEDIA_INFO，故定义足够的空间
//#define MEDIA_INFO_SIZE  sizeof(GET_MEDIA_TYPES)+15*sizeof(DEVICE_MEDIA_INFO)
//
//// filename -- 用于设备的文件名
//// pdg -- 参数缓冲区指针
//BOOL GetDriveGeometry(CString filename, DISK_GEOMETRY *pdg)
//{
//	HANDLE hDevice;         // 设备句柄
//	BOOL bResult;           // DeviceIoControl的返回结果
//	GET_MEDIA_TYPES *pmt;   // 内部用的输出缓冲区
//	DWORD dwOutBytes;       // 输出数据长度
//
//	// 打开设备
//	hDevice = ::CreateFile(filename,                           // 文件名
//		GENERIC_READ,                              // 软驱需要读盘
//		FILE_SHARE_READ | FILE_SHARE_WRITE,        // 共享方式
//		NULL,                                      // 默认的安全描述符
//		OPEN_EXISTING,                             // 创建方式
//		0,                                         // 不需设置文件属性
//		NULL);                                     // 不需参照模板文件
//
//	if (hDevice == INVALID_HANDLE_VALUE)
//	{
//		// 设备无法打开...
//		return FALSE;
//	}
//
//	// 用IOCTL_DISK_GET_DRIVE_GEOMETRY取磁盘参数
//	bResult = ::DeviceIoControl(hDevice,                   // 设备句柄
//		IOCTL_DISK_GET_DRIVE_GEOMETRY,         // 取磁盘参数
//		NULL, 0,                               // 不需要输入数据
//		pdg, sizeof(DISK_GEOMETRY),            // 输出数据缓冲区
//		&dwOutBytes,                           // 输出数据长度
//		(LPOVERLAPPED)NULL);                   // 用同步I/O
//
//	// 如果失败，再用IOCTL_STORAGE_GET_MEDIA_TYPES_EX取介质类型参数
//	if (!bResult)
//	{
//		pmt = (GET_MEDIA_TYPES *) new BYTE[MEDIA_INFO_SIZE];
//
//		bResult = ::DeviceIoControl(hDevice,                 // 设备句柄
//			IOCTL_STORAGE_GET_MEDIA_TYPES_EX,    // 取介质类型参数
//			NULL, 0,                             // 不需要输入数据
//			pmt, MEDIA_INFO_SIZE,                // 输出数据缓冲区
//			&dwOutBytes,                         // 输出数据长度
//			(LPOVERLAPPED)NULL);                 // 用同步I/O 
//
//		if (bResult)
//		{
//			// 注意到结构DEVICE_MEDIA_INFO是在结构DISK_GEOMETRY的基础上扩充的
//			// 为简化程序，用memcpy代替如下多条赋值语句：
//			// pdg->MediaType = (MEDIA_TYPE)pmt->MediaInfo[0].DeviceSpecific.DiskInfo.MediaType;
//			// pdg->Cylinders = pmt->MediaInfo[0].DeviceSpecific.DiskInfo.Cylinders;
//			// pdg->TracksPerCylinder = pmt->MediaInfo[0].DeviceSpecific.DiskInfo.TracksPerCylinder;
//			// ... ...
//			::memcpy(pdg, pmt->MediaInfo, sizeof(DISK_GEOMETRY));
//		}
//
//		delete pmt;
//	}
//
//	// 关闭设备句柄
//	::CloseHandle(hDevice);
//
//	return (bResult);
//}



int CMyDiskInfo::GetDiskInfo(int driver)
{
	CString sFilePath;
	sFilePath.Format(_T("\\\\.\\PHYSICALDRIVE%d"), driver);

	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = ::CreateFile(sFilePath, 
						GENERIC_READ | GENERIC_WRITE, 
						FILE_SHARE_READ | FILE_SHARE_WRITE, 
						NULL, OPEN_EXISTING,
						0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)	return -1;

	DWORD dwBytesReturned;
	GETVERSIONINPARAMS gvopVersionParams;
	DeviceIoControl(hFile, 
					SMART_GET_VERSION,
					NULL, 
					0, 
					&gvopVersionParams,
					sizeof(gvopVersionParams),
					&dwBytesReturned, NULL);

	if(gvopVersionParams.bIDEDeviceMap <= 0)	return -2;

	// IDE or ATAPI IDENTIFY cmd
	int btIDCmd = 0;
	SENDCMDINPARAMS InParams;
	int nDrive =0;
	btIDCmd = (gvopVersionParams.bIDEDeviceMap >> nDrive & 0x10) ? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;
	

	// 输出参数
	BYTE btIDOutCmd[sizeof(SENDCMDOUTPARAMS) + IDENTIFY_BUFFER_SIZE - 1];

	if(DoIdentify(hFile,
					&InParams, 
					(PSENDCMDOUTPARAMS)btIDOutCmd,
					(BYTE)btIDCmd, 
					(BYTE)nDrive, &dwBytesReturned) == FALSE)	return -3;
	::CloseHandle(hFile);

	DWORD dwDiskData[256];
	USHORT *pIDSector; // 对应结构IDSECTOR，见头文件

	pIDSector = (USHORT*)((SENDCMDOUTPARAMS*)btIDOutCmd)->bBuffer;
	for(int i=0; i < 256; i++)	dwDiskData[i] = pIDSector[i];

	// 取系列号
	ZeroMemory(szSerialNumber, sizeof(szSerialNumber));
	strcpy(szSerialNumber, ConvertToString(dwDiskData, 10, 19));

	// 取模型号
	ZeroMemory(szModelNumber, sizeof(szModelNumber));
	strcpy(szModelNumber, ConvertToString(dwDiskData, 27, 46));

	return 0;
}


