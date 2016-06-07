

#include "stdafx.h"
#include <windows.h>
#include <atlstr.h>
#include "tinystr.h"
#include "tinyxml.h"
#include "rapidxml.hpp"
#include "rapidxml_print.hpp"
#include "rapidxml_utils.hpp"
#include <vector>
#include <opencv.hpp>
#include "MyDiskInfo.h"

std::vector<TiXmlElement*> FirewallItem;
std::vector<CString> EnvironmentItem;
std::vector<TiXmlElement*> SoftwareItem;



bool UTF16FileRead(const std::string& path, std::vector<std::wstring> &vec_lines)
{
	/*****************打开文件***********************************************/
	vec_lines.clear();
	std::ifstream fin;
	fin.open(path.c_str(), std::ios::in | std::ios::binary);
	if (!fin.is_open())
	{
		//std::cerr << "Open " << path << " error!" << std::endl;
		return false;
	}
	char  buffer[3] = { '\0' };
	fin.read(buffer, 2);
	int  file_format = 0;/*指示文件格式，1Linux,2Windows*/
	std::string utf16flag = "\xff\xfe";
	std::string fileflag = buffer;
	if ((fileflag.length() >= 2) && (fileflag.at(0) == '\xff') && (fileflag.at(1) == '\xfe'))
	{
		fileflag = fileflag.substr(0, 2);
	}
	if (fileflag != utf16flag)
	{
		//std::cerr << "File " << path << " type error!" << std::endl;
		return false;
	}
	/*处理Unicode编码文件*/
	const int clength = 3;
	char cc[clength] = { '\0' };/*当前读入的字符*/
	char pc[clength] = { '\0' };/*当前的前驱字符*/
	std::string line = "";
	int lineIndex = 0;
	while (fin.read(cc, 2))
	{	/*一次读入两个字节*/
		line += cc[0];
		line += cc[1];
		if ((cc[0] == '\x0a') && (cc[1] == '\x00'))
		{
			if (file_format == 0)
			{
				if ((pc[0] == '\x0d') && (pc[1] == '\x00'))
				{
					file_format = 2;
				}
				else
				{
					file_format = 1;
				}
			}
			if (((file_format == 1) && (line.length() == 2)) || ((file_format == 2) && (line.length() == 4)))
			{
				/*表示空行*/
				line.clear();
				vec_lines.push_back(L"");
				continue;
			}
			/*换行符标志*/
			/*Unicode文件的字节流转换为宽字符*/
			if (file_format == 1)
			{
				line = line.substr(0, line.length() - 2);
			}
			else if (file_format == 2)
			{
				line = line.substr(0, line.length() - 4);
			}
			std::wstring result = L"";
			for (unsigned i = 0; i<line.length() - 1; i += 2)
			{
				unsigned char c1 = line[i];
				unsigned char c2 = line[i + 1];
				unsigned short wc;
				if (c2 == 0)
				{
					wc = c1;
				}
				else
				{
					wc = c2;
					wc = wc << 8;
					wc += c1;
				}
				result += wc;
			}
			vec_lines.push_back(result);
			/*********************/
			result.clear();
			line.clear();
			/*********************/
			lineIndex++;
		}
		if (file_format == 0)
		{
			strcpy_s(pc, cc);/*保存当前两个字符的前驱字符*/
			memset(cc, '\0', sizeof(char)*clength);
		}
	}
	if (!line.empty())
	{
		std::wstring result = L"";
		for (unsigned i = 0; i<line.length() - 1; i += 2)
		{
			unsigned char c1 = line[i];
			unsigned char c2 = line[i + 1];
			unsigned short wc;
			if (c2 == 0)
			{
				wc = c1;
			}
			else
			{
				wc = c2;
				wc = wc << 8;
				wc += c1;
			}
			result += wc;
		}
		vec_lines.push_back(result);
	}
	fin.close();
	return true;
}
void GetMemoryInfo(TiXmlElement *memory)
{
	double var;
	char buffer[100];
	ZeroMemory(buffer, 100);
	MEMORYSTATUS memoryStatus;
	memset(&memoryStatus, sizeof(MEMORYSTATUS), 0);
	memoryStatus.dwLength = sizeof(MEMORYSTATUS);
	GlobalMemoryStatus(&memoryStatus);
	var = memoryStatus.dwTotalPhys / (1024 * 1024);
	sprintf_s(buffer, "%0.0fMB", var);
	
	//var = memoryStatus.dwAvailPhys / (1024 * 1024);
	//sprintf_s(buffer, "%0.0fMB", var);
	memory->SetAttribute("memory", buffer);
}

CString GetInfo(HKEY Key, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, size_t strsize = 256)
{
	CString retString;
	HKEY hKey;
	DWORD dwSize;
	wchar_t *datachar = new wchar_t[strsize];
	DWORD datadword;
	int sizeoflpValueName = sizeof(lpValueName) / sizeof(lpValueName[0]);
	if (RegOpenKey(Key, lpSubKey, &hKey) == ERROR_SUCCESS)
	{
		dwSize = strsize;
		if (dwType == REG_DWORD||dwType == REG_BINARY)
		{
			long ret = 0;
			ret = RegQueryValueEx(hKey, lpValueName, NULL, &dwType, (LPBYTE)&datadword, &dwSize);
			if (ret == ERROR_SUCCESS)
			{
				retString.Format(_T("%d"), datadword);
			}
			else if (ret == 2)
			{
			}
			else
			{
				retString += _T("数据读取出错");
			}
		}
		if (dwType == REG_SZ || dwType == REG_EXPAND_SZ || dwType == REG_MULTI_SZ)
		{
			long ret = 0;
			ret = RegQueryValueEx(hKey, lpValueName, NULL, &dwType, (LPBYTE)datachar, &dwSize);
			if (ret == ERROR_SUCCESS)
			{
				retString.Format(_T("%s"), datachar);
			}
			else if (ret == 2)
			{
			}
			else
			{
				retString += _T("数据读取出错");
			}
		}

	}
	else
	{
		retString += "注册表打开出错";
	}
	RegCloseKey(hKey);
	delete[]datachar;
	return retString;
}
void GetCPUInfo(TiXmlElement *CPU)
{
	USES_CONVERSION;
	
	CString ProcessorNameString = GetInfo(HKEY_LOCAL_MACHINE, _T("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"), _T("ProcessorNameString"), REG_SZ);
	CString MHz = GetInfo(HKEY_LOCAL_MACHINE, _T("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"), _T("~MHz"), REG_DWORD);
	SYSTEM_INFO si;
	memset(&si, 0, sizeof(SYSTEM_INFO));
	GetSystemInfo(&si);
	int Num = si.dwNumberOfProcessors;
	CString num;
	num.Format(_T("%d"), Num);
	CPU->SetAttribute("ProcessorNameString", T2A(ProcessorNameString));
	CPU->SetAttribute("MHz", T2A(MHz));
	CPU->SetAttribute("CoreNumber", T2A(num));

	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX2))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX2");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_FMA3))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_FMA3");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX_512PF))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX_512PF");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX_512VBMI))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX_512VBMI");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX_512VL))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX_512VL");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX_512F))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX_512F");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX_512BW))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX_512BW");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX_512CD))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX_512CD");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX_512DQ))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX_512DQ");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX_512ER))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX_512ER");
	}
	if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_AVX_512IFMA512))
	{
		TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
		CPU->LinkEndChild(item);
		item->SetAttribute("ItemName", "CPU_AVX_512IFMA512");
	}



			if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_MMX))
			{
				TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
				CPU->LinkEndChild(item);
				item->SetAttribute("ItemName", "CPU_MMX");
			}

			if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_SSE))
			{
				TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
				CPU->LinkEndChild(item);
				item->SetAttribute("ItemName", "CPU_SSE");
			}

			if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_SSE2))
			{
				TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
				CPU->LinkEndChild(item);
				item->SetAttribute("ItemName", "CPU_SSE2");
			}

			if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_SSE3))
			{
				TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
				CPU->LinkEndChild(item);
				item->SetAttribute("ItemName", "CPU_SSE3");
			}

			if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_SSSE3))
			{
				TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
				CPU->LinkEndChild(item);
				item->SetAttribute("ItemName", "CPU_SSSE3");
			}

			if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_SSE4_1))
			{
				TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
				CPU->LinkEndChild(item);
				item->SetAttribute("ItemName", "CPU_SSE4_1");
			}

			if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_SSE4_2))
			{
				TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
				CPU->LinkEndChild(item);
				item->SetAttribute("ItemName", "CPU_SSE4_2");
			}

			if (cv::checkHardwareSupport(cv::CpuFeatures::CPU_POPCNT))
			{
				TiXmlElement *item = new TiXmlElement("CpuFeatureItem");
				CPU->LinkEndChild(item);
				item->SetAttribute("ItemName", "CPU_POPCNT");
			}


	
}

void DeleteEnvironmentInfo(CString path)
{
	USES_CONVERSION;
	HKEY hKey;
	CString retString = GetInfo(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"), _T("Path"), REG_SZ, 1024 * 4);
	int f = retString.Find(path);
	while (f != -1)
	{
		char a = retString.GetAt(f + path.GetLength());
		char b = retString.GetAt(f - 1);
		int aa = f + path.GetLength();
		int bb = retString.GetLength();
			if ((f == 0 || retString.GetAt(f - 1) == ';') && ((f + path.GetLength() == retString.GetLength()) || (retString.GetAt(f + path.GetLength()) == ';')))
			{
				if (RegOpenKey(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"), &hKey) == ERROR_SUCCESS)
				{
					CString retString1 = retString.Left(f);
					CString retString2 = retString.Right(retString.GetLength() - f - path.GetLength());
					if (retString2.Find(';') == -1)
					{
						wchar_t a = retString1.GetAt(retString1.GetLength() - 1);
						if (a = ';')
						{
							retString = retString1.Left(retString1.GetLength() - 1);
						}
						else
						{
							retString = retString1;
						}
					}
					else
					{
						wchar_t a = retString1.GetAt(retString1.GetLength() - 1);
						if (a = ';')
						{
							retString1 = retString1.Left(retString1.GetLength() - 1);
						}
						retString = retString1 + retString2;
					}
					int ret = RegSetValueEx(hKey, _T("Path"), NULL, REG_SZ, (LPBYTE)retString.GetBuffer(retString.GetLength()), retString.GetLength() * 2);
					RegCloseKey(hKey);
					break;
				}
			}
			f = retString.Find(';', f + path.GetLength());
			if (f == -1)
			{
				break;
			}
			f = retString.Find(path, f);
	}
}


void AddEnvironmentInfo(CString path)
{
	USES_CONVERSION;
	HKEY hKey;
	CString retString = GetInfo(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"), _T("Path"), REG_SZ,1024*4);
	int f = retString.Find(path);
	while (f != -1)
	{
		if ((f == 0 || retString.GetAt(f - 1) == ';') && ((f + path.GetLength() == retString.GetLength()) || (retString.GetAt(f + path.GetLength()) == ';')))
		{
			return;
		}
		f = retString.Find(';', f + path.GetLength());
		if (f==-1)
		{
			break;
		}
		f = retString.Find(path, f);
	}
	if (RegOpenKey(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"), &hKey) == ERROR_SUCCESS)
	{
		if ((f + path.GetLength() == retString.GetLength())&&retString.GetAt(retString.GetLength() - 1) == ';')
		{
			retString = retString + path;
		}
		else
		{
			retString = retString + _T(";") + path;
		}
		int ret = RegSetValueEx(hKey, _T("Path"), NULL, REG_SZ, (LPBYTE)retString.GetBuffer(retString.GetLength()), retString.GetLength() * 2);
		RegCloseKey(hKey);
	}
}


void SetFirewallRule(int set[2],CString ID)
{
	USES_CONVERSION;
	HKEY hKey;

	  
	//if (RegOpenKey(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile"), &hKey) == ERROR_SUCCESS)
	//{
	//	CString retString;
	//	retString.Format(_T("%d"), set[0]);
	//	int ret = RegSetValueEx(hKey, _T("Path"), NULL, REG_DWORD, (LPBYTE)retString.GetBuffer(retString.GetLength()), retString.GetLength() * 2);
	//	RegCloseKey(hKey);
	//}



	int AN = 0;        //Action=Block
	int AV = 0;			//Active="FALSE"
	int iset = 0;
//	CString EnableFirewall = GetInfo(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile"), _T("EnableFirewall"), REG_DWORD);
	CString retIDString = GetInfo(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"), ID, REG_SZ, 1024 * 4);
	int f = retIDString.Find(_T("=Allow|"));
	if (f!=-1)
	{
		AN = 1;
	}
	f = retIDString.Find(_T("=TRUE|"));
	if (f != -1)
	{
		AV = 1;
	}
	if (AV != set[0])
	{
		if (AV)
		{
			retIDString.Replace(_T("=TRUE|"), _T("=FALSE|"));
		}
		else
		{
			retIDString.Replace(_T("=FALSE|"), _T("=TRUE|"));
		}
		iset = 1;
	}
	if (AN != set[1])
	{
		if (AN)
		{
			retIDString.Replace(_T("=Allow|"), _T("=Block|"));
		}
		else
		{
			retIDString.Replace(_T("=Block|"), _T("=Allow|"));
		}
		iset = 1;
	}
	if (iset)
	{
		if (RegOpenKey(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"), &hKey) == ERROR_SUCCESS)
		{
			int ret = RegSetValueEx(hKey, ID, NULL, REG_SZ, (LPBYTE)retIDString.GetBuffer(retIDString.GetLength()), retIDString.GetLength() * 2);
			RegCloseKey(hKey);
		}
	}
}


void GetDisplayCardInfo(TiXmlElement *GPU)
{
	USES_CONVERSION;
	HKEY keyServ;
	HKEY keyEnum;
	HKEY key;
	HKEY key2;
	LONG lResult;//LONG型变量－保存函数返回值  

	//查询"SYSTEM\\CurrentControlSet\\Services"下的所有子键保存到keyServ  
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services"), 0, KEY_READ, &keyServ);
	if (ERROR_SUCCESS != lResult)
		return;


	//查询"SYSTEM\\CurrentControlSet\\Enum"下的所有子键保存到keyEnum  
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Enum"), 0, KEY_READ, &keyEnum);
	if (ERROR_SUCCESS != lResult)
		return;

	int i = 0, count = 0,icount = 0;
	DWORD size = 0, type = 0;
	for (;; ++i)
	{
		
		size = 512;
		TCHAR name[512] = { 0 };//保存keyServ下各子项的字段名称  

		//逐个枚举keyServ下的各子项字段保存到name中  
		lResult = RegEnumKeyEx(keyServ, i, name, &size, NULL, NULL, NULL, NULL);

		//要读取的子项不存在，即keyServ的子项全部遍历完时跳出循环  
		if (lResult == ERROR_NO_MORE_ITEMS)
			break;

		//打开keyServ的子项字段为name所标识的字段的值保存到key  
		lResult = RegOpenKeyEx(keyServ, name, 0, KEY_READ, &key);
		if (lResult != ERROR_SUCCESS)
		{
			RegCloseKey(keyServ);
			return;
		}


		size = 512;
		//查询key下的字段为Group的子键字段名保存到name  
		lResult = RegQueryValueEx(key, TEXT("Group"), 0, &type, (LPBYTE)name, &size);
		if (lResult == ERROR_FILE_NOT_FOUND)
		{
			//?键不存在  
			RegCloseKey(key);
			continue;
		}


		//如果查询到的name不是Video则说明该键不是显卡驱动项  
		if (_tcscmp(TEXT("Video"), name) != 0)
		{
			RegCloseKey(key);
			continue;     //返回for循环  
		}

		//如果程序继续往下执行的话说明已经查到了有关显卡的信息，所以在下面的代码执行完之后要break第一个for循环，函数返回  
		lResult = RegOpenKeyEx(key, TEXT("Enum"), 0, KEY_READ, &key2);
		RegCloseKey(key);
		key = key2;
		size = sizeof(count);


		lResult = RegQueryValueEx(key, TEXT("Count"), 0, &type, (LPBYTE)&count, &size);//查询Count字段（显卡数目）  

		for (int j = 0; j < count; ++j)
		{
			TCHAR sz[512] = { 0 };
			TCHAR name[64] = { 0 };
			wsprintf(name, TEXT("%d"), j);
			size = sizeof(sz);
			lResult = RegQueryValueEx(key, name, 0, &type, (LPBYTE)sz, &size);

			
			lResult = RegOpenKeyEx(keyEnum, sz, 0, KEY_READ, &key2);


			//LONG lRet = ERROR_SUCCESS;
			//TCHAR szName[1024];
			//DWORD cbValue = 1024;
			//DWORD dwType;
			//int i = 0;
			//DWORD dwSize;
			//DWORD datadword;
			//while (lRet == ERROR_SUCCESS){
			//	CString retString;
			//	cbValue = 1024;
			//	dwSize = 1024;
			//	memset(szName, 0, 1024);
			//	lRet = RegEnumValue(key2, i, szName, &cbValue, NULL, &dwType, NULL, NULL);
			//	if (dwType == REG_DWORD)
			//	{
			//		if (RegQueryValueEx(key2, szName, NULL, &dwType, (LPBYTE)&datadword, &dwSize) == ERROR_SUCCESS)
			//		{
			//			retString.Format(_T("%d"), datadword);
			//		}
			//		else
			//		{
			//			retString += _T("数据读取出错");
			//		}
			//	}
			//	if (dwType == REG_SZ || dwType == REG_EXPAND_SZ || dwType == REG_MULTI_SZ)
			//	{
			//		wchar_t *datachar = new wchar_t[dwSize];
			//		//long ret = RegQueryValueEx(hKey, szName, NULL, &dwType, (LPBYTE)datachar, &dwSize);
			//		if (RegQueryValueEx(key2, szName, NULL, &dwType, (LPBYTE)datachar, &dwSize) == ERROR_SUCCESS)
			//		{
			//			retString.Format(_T("%s"), datachar);
			//		}
			//		else
			//		{
			//			retString += _T("数据读取出错");
			//		}
			//		delete[]datachar;
			//	}
			//	++i;
			//}

			if (lResult != ERROR_SUCCESS)
			{
				RegCloseKey(keyEnum);
				return;
			}
			CString GPUName;
			CString DriverName;
			size = sizeof(sz);
			lResult = RegQueryValueEx(key2, TEXT("FriendlyName"), 0, &type, (LPBYTE)sz, &size);
			if (lResult == ERROR_FILE_NOT_FOUND)
			{
				//size = sizeof(sz);
				//lResult = RegQueryValueEx(key2, TEXT("DeviceDesc"), 0, &type, (LPBYTE)sz, &size);
				//GPUName = sz;//保存显卡名称
				size = sizeof(sz);
				lResult = RegQueryValueEx(key2, TEXT("Driver"), 0, &type, (LPBYTE)sz, &size);
				DriverName = sz;
				if (DriverName.IsEmpty())
				{
					continue;
				}
				CString SubKey = _T("SYSTEM\\CurrentControlSet\\Control\\Class\\") + DriverName;
				CString GPUName = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("DriverDesc"), REG_SZ);
				CString MemorySize = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("HardwareInformation.MemorySize"), REG_DWORD);
				int Size = _ttoi(MemorySize);
				MemorySize.Format(_T("%dMB"), Size / 1024 / 1024);
				TiXmlElement* Driver = new TiXmlElement("Driver");
				GPU->LinkEndChild(Driver);
				Driver->SetAttribute("Name", T2A(GPUName));
				Driver->SetAttribute("MemorySize", T2A(MemorySize));
				++icount;
			}
			RegCloseKey(key2);
			key2 = NULL;
		}
		RegCloseKey(key);
		key = NULL;
	}
	CString ccount;
	ccount.Format(_T("%d"), icount);
	GPU->SetAttribute("Count", T2A(ccount));
}

void GetFirewallRules(TiXmlElement *Firewall)
{
	USES_CONVERSION;
	HKEY key2;
	int lResult = 0;
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"), 0, KEY_READ, &key2);
	LONG lRet = ERROR_SUCCESS;
	TCHAR szName[1024];
	DWORD cbValue = 1024;
	DWORD dwType;
	int i = 0;
	DWORD dwSize;
	while (lRet == ERROR_SUCCESS){
		CString retString;
		cbValue = 1024;
		dwSize = 1024;
		memset(szName, 0, 1024);
		lRet = RegEnumValue(key2, i, szName, &cbValue, NULL, &dwType, NULL, NULL);

		if ((szName[0] != '{' )&& (szName[0]!='T')&& (szName[0]!='U'))
		{
			++i;
			continue;
		}
		if ((szName[0] == 'T') && (szName[14] != '{') || (szName[0] == 'U') && (szName[14] != '{'))
		{
			++i;
			continue;
		}
		if (dwType == REG_SZ || dwType == REG_EXPAND_SZ || dwType == REG_MULTI_SZ)
		{
			int t = 1;                               //判断是否显示
			wchar_t *datachar = new wchar_t[dwSize];
			if (RegQueryValueEx(key2, szName, NULL, &dwType, (LPBYTE)datachar, &dwSize) == ERROR_SUCCESS)
			{
				
				CString Active, Action, Name, Dir, Protocol, App, LPort, RPort, Profile;
				
				auto ff = [&datachar, &retString](CString findname){
					retString.Format(_T("%s"), datachar);
					retString = retString.Right(retString.GetLength() - retString.Find(findname) - findname.GetLength());
					return retString = retString.Left(retString.Find('|'));
				};
				Active = ff(_T("|Active="));
				//retString.Format(_T("%s"), datachar);
				//retString = retString.Right(retString.GetLength() - retString.Find(_T("|Active=")) - 8);
				//retString = retString.Left(retString.Find('|'));		
				//Active = retString;
				

				retString.Format(_T("%s"), datachar);
				retString = retString.Right(retString.GetLength() - retString.Find(_T("|Action=")) - 8);
				retString = retString.Left(retString.Find('|'));
				Action = retString;
				

				retString.Format(_T("%s"), datachar);
				retString = retString.Right(retString.GetLength() - retString.Find(_T("|Name="))-6);
				retString = retString.Left(retString.Find('|'));
				Name = retString;
				

				retString.Format(_T("%s"), datachar);
				retString = retString.Right(retString.GetLength() - retString.Find(_T("|Dir=")) - 5);
				retString = retString.Left(retString.Find('|'));
				Dir = retString;
				

				retString.Format(_T("%s"), datachar);
				retString = retString.Right(retString.GetLength() - retString.Find(_T("|Protocol=")) - 10);
				retString = retString.Left(retString.Find('|'));
				if (retString =="17")
				{
					Protocol = _T("UDP");
				}
				if (retString == "6")
				{
					Protocol = _T("TDP");			
				}

				retString.Format(_T("%s"), datachar);
				if (retString.Find(_T("|Profile=")) != -1)
				{
					retString = retString.Right(retString.GetLength() - retString.Find(_T("|Profile=")) - 9);
					retString = retString.Left(retString.Find('|'));
					Profile = retString;
				}

				retString.Format(_T("%s"), datachar);
				if (retString.Find(_T("|LPort=")) != -1)
				{
					retString = retString.Right(retString.GetLength() - retString.Find(_T("|RPort=")) - 7);
					retString = retString.Left(retString.Find('|'));
					LPort = retString;
				}

				retString.Format(_T("%s"), datachar);
				if (retString.Find(_T("|RPort=")) != -1)
				{
					retString = retString.Right(retString.GetLength() - retString.Find(_T("|RPort=")) - 7);
					retString = retString.Left(retString.Find('|'));
					RPort = retString;
				}
				

				retString.Format(_T("%s"), datachar);
				retString = retString.Right(retString.GetLength() - retString.Find(_T("|App=")) - 5);
				retString = retString.Left(retString.Find('|'));
				App = retString;
				

				for (unsigned i = 0; i < FirewallItem.size(); ++i)
				{
					t = 1;
					TiXmlElement* item = FirewallItem.at(i);
					TiXmlAttribute *itemAttribute = item->FirstAttribute();
					while (itemAttribute&&t)
					{
						CString itemName = itemAttribute->Name();
						CString values = itemAttribute->Value();
						if (itemName == _T("App"))
						{
							if (App.Find(values)==-1)
							{
								t = 0;
								break;
							}
						}
						if (itemName == _T("Name"))
						{
							if (Name.Find(values) == -1)
							{
								t = 0;
								break;
							}
						}
						if (itemName == _T("Active"))
						{
							if (Active.Find(values) == -1)
							{
								t = 0;
								break;
							}
						}
						if (itemName == _T("Action"))
						{
							if (Action.Find(values) == -1)
							{
								t = 0;
								break;
							}
						}
						if (itemName == _T("Dir"))
						{
							if (Dir.Find(values) == -1)
							{
								t = 0;
								break;
							}
						}
						if (itemName == _T("Protocol"))
						{
							if (Protocol.Find(values) == -1)
							{
								t = 0;
								break;
							}
						}
						itemAttribute = itemAttribute->Next();
					}
					if (t)
					{
						break;
					}
				}


				if (t)
				{
					
					CString ID = szName;
					if (!Name.IsEmpty())
					{
						TiXmlElement* Display = new TiXmlElement("Item");
						Firewall->LinkEndChild(Display);
						Display->SetAttribute("Active", T2A(Active));
						Display->SetAttribute("Action", T2A(Action));
						Display->SetAttribute("Name", T2A(Name));
						Display->SetAttribute("Dir", T2A(Dir));
						Display->SetAttribute("Protocol", T2A(Protocol));
						if (!Profile.IsEmpty())
						{
							Display->SetAttribute("Profile", T2A(Profile));
						}

						if (!LPort.IsEmpty())
						{
							Display->SetAttribute("LPort", T2A(LPort));
						}
						if (!RPort.IsEmpty())
						{
							Display->SetAttribute("RPort", T2A(RPort));
						}
						Display->SetAttribute("App", T2A(App));
						Display->SetAttribute("ID", T2A(ID));
					}
					
				}
				
			}
			else
			{
				retString += _T("数据读取出错");
			}
			delete[]datachar;
		}
		++i;
	}
	RegCloseKey(key2);
	return;
}




void NetworkCardsInfo(TiXmlElement *Network)
{
	USES_CONVERSION;
	DWORD dwIndex = 0;
	HKEY hKey;
	CString strKey = _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards");
	CString strKeyName;
	DWORD dwNameSize = 256;
	if (RegOpenKey(HKEY_LOCAL_MACHINE,strKey , &hKey) == ERROR_SUCCESS)
	{

		LONG lRet = RegEnumKeyEx(hKey, dwIndex, strKeyName.GetBuffer(dwNameSize), &dwNameSize, 0, NULL, NULL, NULL);
		while (ERROR_SUCCESS == lRet)
		{
			TiXmlElement* Item = new TiXmlElement("Item");
			Network->LinkEndChild(Item);
			dwIndex++;
			dwNameSize = 256;
			CString SubKey = strKey + strKeyName;
			SubKey.Format(_T("%s\\%s"), strKey, strKeyName);
			CString Description = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("Description"), REG_SZ);
			CString ServiceName = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("ServiceName"), REG_SZ);
			CString kk = _T("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces");
			SubKey.Format(_T("%s\\%s"),kk, ServiceName);
			//{43DC81E2-1E1C-49E4-B76C-CDA567F4A839}
			CString ProductName = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("EnableDHCP"), REG_DWORD);
			CString IPAddress;
			CString DefaultGateway;
			CString SubnetMask;
			if (ProductName == "0")
			{
				IPAddress = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("IPAddress"), REG_SZ);
				DefaultGateway = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("DefaultGateway"), REG_SZ);
				SubnetMask = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("SubnetMask"), REG_SZ);	
			}
			if (ProductName == "1")
			{
				IPAddress = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("DhcpIPAddress"), REG_SZ);
				DefaultGateway = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("DhcpDefaultGateway"), REG_SZ);
				SubnetMask = GetInfo(HKEY_LOCAL_MACHINE, SubKey, _T("SubnetMask"), REG_SZ);
			}
			Item->SetAttribute("Description", T2A(Description));
			Item->SetAttribute("IPAddress", T2A(IPAddress));
			Item->SetAttribute("Gateway", T2A(DefaultGateway));
			Item->SetAttribute("netMask", T2A(SubnetMask));
			lRet = RegEnumKeyEx(hKey, dwIndex, strKeyName.GetBuffer(dwNameSize), &dwNameSize, 0, NULL, NULL, NULL);
		}
	}
	RegCloseKey(hKey);
}



void SoftwareInfo(TiXmlElement *Software)
{
	USES_CONVERSION;
	DWORD dwIndex = 0;
	HKEY hKey;
	CString strKey = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
	CString strKeyName;
	DWORD dwNameSize = 256;
	DWORD ii = 0;
	if (RegOpenKey(HKEY_LOCAL_MACHINE, strKey, &hKey) == ERROR_SUCCESS)
	{

		LONG lRet = RegEnumKeyEx(hKey, dwIndex, strKeyName.GetBuffer(dwNameSize), &dwNameSize, 0, NULL, NULL, NULL);
		while (ERROR_SUCCESS == lRet)
		{
	
			dwIndex++;
			dwNameSize = 256;
			CString Display;
			Display.Format(_T("%s\\%s"), strKey, strKeyName);
			CString DisplayName = GetInfo(HKEY_LOCAL_MACHINE, Display, _T("DisplayName"), REG_SZ);
			CString DisplayVersion = GetInfo(HKEY_LOCAL_MACHINE, Display, _T("DisplayVersion"), REG_SZ);
			CString InstallLocation = GetInfo(HKEY_LOCAL_MACHINE, Display, _T("InstallLocation"), REG_SZ);
			CString Publisher = GetInfo(HKEY_LOCAL_MACHINE, Display, _T("Publisher"), REG_SZ);
			CString SystemComponent = GetInfo(HKEY_LOCAL_MACHINE, Display, _T("SystemComponent"), REG_DWORD);
			int t = 1;    //判断显示
			if (!DisplayName.IsEmpty())
			{
				for (unsigned i = 0; i < SoftwareItem.size(); ++i)
				{
					t = 1;
					TiXmlElement* item = SoftwareItem.at(i);
					TiXmlAttribute *itemAttribute = item->FirstAttribute();
					while (itemAttribute&&t)
					{
						CString itemName = itemAttribute->Name();
						CString values = itemAttribute->Value();
						if (itemName == _T("Name"))
						{
							if (DisplayName.Find(values) == -1)
							{
								t = 0;
							}
						}
						itemAttribute = itemAttribute->Next();
					}
					if (t)
					{
						break;
					}
				}


				if (t)
				{
					++ii;

					TiXmlElement* Display = new TiXmlElement("Item");
					Software->LinkEndChild(Display);
					Display->SetAttribute("Name", T2A(DisplayName));
					Display->SetAttribute("DisplayVersion", T2A(DisplayVersion));
					Display->SetAttribute("InstallLocation", T2A(InstallLocation));
					Display->SetAttribute("Publisher", T2A(Publisher));
					Display->SetAttribute("SystemComponent", T2A(SystemComponent));
				}

			}


			
			lRet = RegEnumKeyEx(hKey, dwIndex, strKeyName.GetBuffer(dwNameSize), &dwNameSize, 0, NULL, NULL, NULL);
		}
	}
	RegCloseKey(hKey);
	if (RegOpenKey(HKEY_CURRENT_USER, strKey, &hKey) == ERROR_SUCCESS)
	{
		dwIndex = 0;
		LONG lRet = RegEnumKeyEx(hKey, dwIndex, strKeyName.GetBuffer(dwNameSize), &dwNameSize, 0, NULL, NULL, NULL);
		while (ERROR_SUCCESS == lRet)
		{

			dwIndex++;
			dwNameSize = 256;
			CString Display;
			Display.Format(_T("%s\\%s"), strKey, strKeyName);
			CString DisplayName = GetInfo(HKEY_CURRENT_USER, Display, _T("DisplayName"), REG_SZ);
			CString DisplayVersion = GetInfo(HKEY_CURRENT_USER, Display, _T("DisplayVersion"), REG_SZ);
			CString InstallLocation = GetInfo(HKEY_CURRENT_USER, Display, _T("InstallLocation"), REG_SZ);
			CString Publisher = GetInfo(HKEY_CURRENT_USER, Display, _T("Publisher"), REG_SZ);
			CString SystemComponent = GetInfo(HKEY_CURRENT_USER, Display, _T("SystemComponent"), REG_DWORD);
			int t = 1;    //判断显示
			if (!DisplayName.IsEmpty())
			{
				for (unsigned i = 0; i < SoftwareItem.size(); ++i)
				{
					t = 1;
					TiXmlElement* item = SoftwareItem.at(i);
					TiXmlAttribute *itemAttribute = item->FirstAttribute();
					while (itemAttribute&&t)
					{
						CString itemName = itemAttribute->Name();
						CString values = itemAttribute->Value();
						if (itemName == _T("Name"))
						{
							if (DisplayName.Find(values) == -1)
							{
								t = 0;
							}
						}
						itemAttribute = itemAttribute->Next();
					}
					if (t)
					{
						break;
					}
				}
				

				if (t)
				{
					++ii;
					TiXmlElement* Display = new TiXmlElement("Item");
					Software->LinkEndChild(Display);
					Display->SetAttribute("Name", T2A(DisplayName));
					Display->SetAttribute("DisplayVersion", T2A(DisplayVersion));
					Display->SetAttribute("InstallLocation", T2A(InstallLocation));
					Display->SetAttribute("Publisher", T2A(Publisher));
					Display->SetAttribute("SystemComponent", T2A(SystemComponent));
				}
				
			}
			lRet = RegEnumKeyEx(hKey, dwIndex, strKeyName.GetBuffer(dwNameSize), &dwNameSize, 0, NULL, NULL, NULL);
		}
	}
	RegCloseKey(hKey);
	
	Software->SetAttribute("Count", ii);
}
void EnvironmentInfo(TiXmlElement *Environment)
{
	USES_CONVERSION;
	HKEY hKey;
	LONG lRet = ERROR_SUCCESS;
	TCHAR szName[1024];
	DWORD cbValue = 1024;
	DWORD dwType;
	int i = 0;
	DWORD dwSize;
	DWORD datadword;
//	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"), 0, dwDesire, &m_hKey) == ERROR_SUCCESS)
	if (RegOpenKey(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"), &hKey) == ERROR_SUCCESS)
	while (lRet == ERROR_SUCCESS)
	{
		
		CString retString;
		cbValue = 1024;
		dwSize = 2048*4;
		memset(szName, 0, 1024);
		lRet = RegEnumValue(hKey, i, szName, &cbValue, NULL, &dwType, NULL, NULL);
		if (dwType == REG_DWORD)
		{
			if (RegQueryValueEx(hKey, szName, NULL, &dwType, (LPBYTE)&datadword, &dwSize) == ERROR_SUCCESS)
			{
				retString.Format(_T("%d"), datadword);
			}
			else
			{
				retString += _T("数据读取出错");
			}
		}
		if (dwType == REG_SZ || dwType == REG_EXPAND_SZ ||dwType == REG_MULTI_SZ)
		{
			wchar_t *datachar = new wchar_t[dwSize];
			//long ret = RegQueryValueEx(hKey, szName, NULL, &dwType, (LPBYTE)datachar, &dwSize);
			if (RegQueryValueEx(hKey, szName, NULL, &dwType, (LPBYTE)datachar, &dwSize) == ERROR_SUCCESS)
			{
				retString.Format(_T("%s"), datachar);
			}
			else
			{
				retString += _T("数据读取出错");
			}
			delete[]datachar;
		}
		if (lRet == ERROR_SUCCESS)
		{
			CString sname = szName;
			if (sname == _T("Path"))
			{
				TiXmlElement* Name_Values = new TiXmlElement("Path");
				Environment->LinkEndChild(Name_Values);
				while (1)
				{		
					
					if (retString.Find(';') == -1)
					{
						CString Path = retString;
						if (EnvironmentItem.size()>0)
						{
							for (unsigned i = 0; i < EnvironmentItem.size(); ++i)
							{
								if (EnvironmentItem.at(i) == Path)
								{
									if (!Path.IsEmpty())
									{
										TiXmlElement* Item = new TiXmlElement("Item");
										Name_Values->LinkEndChild(Item);
										Item->SetAttribute("Name", T2A(Path));
									}
									break;
								}
							}
							break;
						}
						else
						{
							if (!Path.IsEmpty())
							{
								TiXmlElement* Item = new TiXmlElement("Item");
								Name_Values->LinkEndChild(Item);
								Item->SetAttribute("Name", T2A(Path));
							}
							break;
						}


					}
					else
					{
						CString Path = retString.Left(retString.Find(';'));
						retString = retString.Right(retString.GetLength() - retString.Find(';') - 1);
						if (EnvironmentItem.size()>0)
						{
							for (unsigned i = 0; i < EnvironmentItem.size(); ++i)
							{
								if (EnvironmentItem.at(i) == Path)
								{
									TiXmlElement* Item = new TiXmlElement("Item");
									Name_Values->LinkEndChild(Item);
									Item->SetAttribute("Name", T2A(Path));
									break;
								}
							}
						}
						else
						{
							TiXmlElement* Item = new TiXmlElement("Item");
							Name_Values->LinkEndChild(Item);
							Item->SetAttribute("Name", T2A(Path));
						}	
					}		
				}
			}
			else
			{
				TiXmlElement* Name_Values = new TiXmlElement(T2A(szName));
				Environment->LinkEndChild(Name_Values);
				Name_Values->SetAttribute(T2A(szName), T2A(retString));
			}
			
		}

		i++;
	}
	RegCloseKey(hKey);
}
void GetDiskInfo(TiXmlElement *Disk, CString Signature)
{
	USES_CONVERSION;
	HKEY key2;
	int lResult = 0;
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SYSTEM\\MountedDevices"), 0, KEY_READ, &key2);
	LONG lRet = ERROR_SUCCESS;
	TCHAR szName[1024];
	DWORD cbValue = 1024;
	DWORD dwType = REG_BINARY;
	int i = 0;
	
	while (lRet == ERROR_SUCCESS){
		cbValue = 1024;
		DWORD dwSize = 32;
		memset(szName, 0, 1024);
		lRet = RegEnumValue(key2, i, szName, &cbValue, NULL, &dwType, NULL, NULL);
		
		if (lRet == ERROR_SUCCESS)
		{
			if (dwType == REG_BINARY)
			{
				dwSize = 32;
				TCHAR datadword[32];
				if (RegQueryValueEx(key2, szName, NULL, &dwType, (LPBYTE)&datadword, &dwSize) == ERROR_SUCCESS)
				{
					DWORD w = *(DWORD*)datadword;
					
					if (_ttoi(Signature) == w)
					{
						CString DriveName;
						DriveName.Format(_T("%s"), szName);
						DriveName.Replace(_T("\\DosDevices\\"), _T(""));
						DriveName.Format(_T("%s\\"), DriveName);
						int name_s = DriveName.GetLength();
						if (name_s == 3)
						{
							BOOL fResult;
							unsigned _int64 i64FreeBytesToCaller;
							unsigned _int64 i64TotalBytes;
							unsigned _int64 i64FreeBytes;
							TiXmlElement* Drive = new TiXmlElement("VolumeItem");
							Disk->LinkEndChild(Drive);
							Drive->SetAttribute("Volume", T2A(DriveName));
							int	DType = GetDriveType(DriveName);

							WCHAR lpVolumeNameBuffer[1024];//磁盘驱动器卷标名称
							DWORD nVolumeNameSize = 1024;
							DWORD lpVolumeSerialNumber;
							DWORD lpMaximumComponentLength;
							DWORD lpFileSystemFlags;
							WCHAR lpFileSystemNameBuffer[1024];//文件操作系统名称
							DWORD nFileSystemNameSize = 1024;
							int ret = 0;
							ret = GetVolumeInformation(DriveName, lpVolumeNameBuffer, nVolumeNameSize, &lpVolumeSerialNumber,
								&lpMaximumComponentLength, &lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);
							if (ret != 0)
							{
								CString VolumeName = lpVolumeNameBuffer;
								Drive->SetAttribute("VolumeName", T2A(VolumeName));
								CString FileSystemName = lpFileSystemNameBuffer;
								Drive->SetAttribute("FileSystemName", T2A(FileSystemName));
							}
							//GetDriveType函数，可以获取驱动器类型，参数为驱动器的根目录
							if (DType == DRIVE_FIXED)
							{
								Drive->SetAttribute("DriveType", "硬盘");
							}
							else if (DType == DRIVE_CDROM)
							{
								Drive->SetAttribute("DriveType", "光驱");
							}
							else if (DType == DRIVE_REMOVABLE)
							{
								Drive->SetAttribute("DriveType", "可移动式磁盘");
							}
							else if (DType == DRIVE_REMOTE)
							{
								Drive->SetAttribute("DriveType", "网络磁盘");
							}
							else if (DType == DRIVE_RAMDISK)
							{
								Drive->SetAttribute("DriveType", "虚拟RAM磁盘");
							}
							else if (DType == DRIVE_UNKNOWN)
							{
								Drive->SetAttribute("DriveType", "未知设备");
							}
							fResult = GetDiskFreeSpaceEx(DriveName, (PULARGE_INTEGER)&i64FreeBytesToCaller, (PULARGE_INTEGER)&i64TotalBytes, (PULARGE_INTEGER)&i64FreeBytes);
							//GetDiskFreeSpaceEx函数，可以获取驱动器磁盘的空间状态,函数返回的是个BOOL类型数据
							if (fResult)//通过返回的BOOL数据判断驱动器是否在工作状态
							{
								CString totalspace;
								CString freespace;
								int i1 = (float)i64TotalBytes / 1024 / 1024;
								int i2 = (float)i64FreeBytesToCaller / 1024 / 1024;
								totalspace.Format(_T("%dMB"), i1);
								freespace.Format(_T("%dMB"), i2);

								Drive->SetAttribute("totalspace", T2A(totalspace));
								Drive->SetAttribute("freespace", T2A(freespace));

							}
						}

					}
				}
			}
		}
		++i;
	}

	RegCloseKey(key2);









	//int DriveCount = 0;
	//CString DiskCount = GetInfo(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\Disk\\Enum"), _T("Count"), REG_DWORD);
	//Disk->SetAttribute("DiskCount", T2A(DiskCount));
	//int Size = _ttoi(DiskCount);
	//for (int i = 0; i < Size;++i)
	//{
	//	CString number;
	//	number.Format(_T("%d"), i);
	//	number = GetInfo(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\Disk\\Enum"), number, REG_SZ);
	//	number = _T("SYSTEM\\CurrentControlSet\\Enum\\") + number;
	//	CString DiskDiverName;
	//	DiskDiverName = GetInfo(HKEY_LOCAL_MACHINE, number, _T("FriendlyName"), REG_SZ);
	//	Disk->SetAttribute("DiskDiverName", T2A(DiskDiverName));
	//}
	//DWORD DiskInfo = GetLogicalDrives();
	//
	////利用GetLogicalDrives()函数可以获取系统中逻辑驱动器的数量，函数返回的是一个32位无符号整型数据。
	//while (DiskInfo)//通过循环操作查看每一位数据是否为1，如果为1则磁盘为真,如果为0则磁盘不存在。
	//{
	//	if (DiskInfo & 1)//通过位运算的逻辑与操作，判断是否为1
	//	{
	//		++DriveCount;
	//	}
	//	DiskInfo = DiskInfo >> 1;//通过位运算的右移操作保证每循环一次所检查的位置向右移动一位。
	//}
	//Disk->SetAttribute("DriveCount", DriveCount);
	////-------------------------------------------------------------------

	//int DSLength = GetLogicalDriveStrings(0, NULL);
	////通过GetLogicalDriveStrings()函数获取所有驱动器字符串信息长度。
	//WCHAR* DStr = new WCHAR[DSLength];//用获取的长度在堆区创建一个c风格的字符串数组
	//GetLogicalDriveStrings(DSLength, (LPTSTR)DStr);
	////通过GetLogicalDriveStrings将字符串信息复制到堆区数组中,其中保存了所有驱动器的信息。
	//int DType;
	//int si = 0;
	//BOOL fResult;
	//unsigned _int64 i64FreeBytesToCaller;
	//unsigned _int64 i64TotalBytes;
	//unsigned _int64 i64FreeBytes;
	//for (int i = 0; i < DSLength / 4; ++i)
	//	//为了显示每个驱动器的状态，则通过循环输出实现，由于DStr内部保存的数据是A:\NULLB:\NULLC:\NULL，这样的信息，所以DSLength/4可以获得具体大循环范围
	//{
	//	TiXmlElement* Drive = new TiXmlElement("Dirve");
	//	Disk->LinkEndChild(Drive);
	//	CString DriveName = DStr + i * 4;
	//	Drive->SetAttribute("DriveName", T2A(DriveName));
	//	DType = GetDriveType(DStr + i * 4);
	//	
	//	WCHAR lpVolumeNameBuffer[1024];//磁盘驱动器卷标名称
	//	DWORD nVolumeNameSize = 1024;  
	//	DWORD lpVolumeSerialNumber ;
	//	DWORD lpMaximumComponentLength;
	//	DWORD lpFileSystemFlags;
	//	WCHAR lpFileSystemNameBuffer[1024];//文件操作系统名称
	//	DWORD nFileSystemNameSize = 1024;
	//	int ret = 0;
	//	ret = GetVolumeInformation(DStr + i * 4, lpVolumeNameBuffer, nVolumeNameSize, &lpVolumeSerialNumber,
	//		&lpMaximumComponentLength, &lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);
	//	if (ret != 0)
	//	{
	//		CString VolumeName = lpVolumeNameBuffer;
	//		Drive->SetAttribute("VolumeName", T2A(VolumeName));
	//		CString FileSystemName = lpFileSystemNameBuffer;
	//		Drive->SetAttribute("FileSystemName", T2A(FileSystemName));
	//	}
	//	//GetDriveType函数，可以获取驱动器类型，参数为驱动器的根目录
	//	if (DType == DRIVE_FIXED)
	//	{
	//		Drive->SetAttribute("DriveType", "硬盘");
	//	}
	//	else if (DType == DRIVE_CDROM)
	//	{
	//		Drive->SetAttribute("DriveType", "光驱");
	//	}
	//	else if (DType == DRIVE_REMOVABLE)
	//	{
	//		Drive->SetAttribute("DriveType", "可移动式磁盘");
	//	}
	//	else if (DType == DRIVE_REMOTE)
	//	{
	//		Drive->SetAttribute("DriveType", "网络磁盘");
	//	}
	//	else if (DType == DRIVE_RAMDISK)
	//	{
	//		Drive->SetAttribute("DriveType", "虚拟RAM磁盘");
	//	}
	//	else if (DType == DRIVE_UNKNOWN)
	//	{
	//		Drive->SetAttribute("DriveType", "未知设备");
	//	}
	//	fResult = GetDiskFreeSpaceEx(DStr + i * 4, (PULARGE_INTEGER)&i64FreeBytesToCaller, (PULARGE_INTEGER)&i64TotalBytes, (PULARGE_INTEGER)&i64FreeBytes);
	//	//GetDiskFreeSpaceEx函数，可以获取驱动器磁盘的空间状态,函数返回的是个BOOL类型数据
	//	if (fResult)//通过返回的BOOL数据判断驱动器是否在工作状态
	//	{
	//		CString totalspace;
	//		CString freespace;
	//		totalspace.Format(_T("%fMB"), (float)i64TotalBytes / 1024 / 1024);
	//		freespace.Format(_T("%fMB"), (float)i64FreeBytesToCaller / 1024 / 1024);

	//		Drive->SetAttribute("totalspace", T2A(totalspace));
	//		Drive->SetAttribute("freespace", T2A(freespace));
	//	//	cout << " totalspace:" << (float)i64TotalBytes / 1024 / 1024 << " MB";//磁盘总容量
	//	//	cout << " freespace:" << (float)i64FreeBytesToCaller / 1024 / 1024 << " MB";//磁盘剩余空间
	//	}	
	//	si += 4;
	//}
}
CString GetAppPath()
{//获取应用程序根目录
	TCHAR modulePath[MAX_PATH];
	GetModuleFileName(NULL, modulePath, MAX_PATH);
	CString strModulePath(modulePath);
	strModulePath = strModulePath.Left(strModulePath.ReverseFind(_T('\\')));
	return strModulePath;
}
bool ReadSetupxml(CString& szFileName)
{
	USES_CONVERSION;
	CString appPath = GetAppPath();
	CString seperator = "\\";
	CString fullPath = appPath.GetBuffer(0) + seperator + szFileName;
	TiXmlDocument *doc =new TiXmlDocument(T2A(fullPath));
	bool loadOkay = doc->LoadFile();
	if (!loadOkay)
	{
		return false;
	}
	TiXmlElement *root = doc->FirstChildElement();
	if (root !=NULL)
	{
		TiXmlElement* Firewall = root->FirstChildElement("Firewall");
		if (Firewall!=NULL)
		{
			CString EnableFirewall = Firewall->Attribute("EnableFirewall");
			HKEY hKey;
			if (EnableFirewall != GetInfo(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile"), _T("EnableFirewall"), REG_DWORD) ||
				EnableFirewall != GetInfo(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"), _T("EnableFirewall"), REG_DWORD))
			{
				if (RegOpenKey(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile"), &hKey) == ERROR_SUCCESS)
				{
					CString retString = EnableFirewall;
					DWORD  ii = _ttoi(retString);

					int ret = RegSetValueEx(hKey, _T("EnableFirewall"), NULL, REG_DWORD, (LPBYTE)&ii, sizeof(DWORD));
					RegCloseKey(hKey);
				}
				if (RegOpenKey(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"), &hKey) == ERROR_SUCCESS)
				{
					CString retString = EnableFirewall;
					DWORD  ii = _ttoi(retString);

					int ret = RegSetValueEx(hKey, _T("EnableFirewall"), NULL, REG_DWORD, (LPBYTE)&ii, sizeof(DWORD));
					RegCloseKey(hKey);
				}
			}


			TiXmlElement* FindDisplay = Firewall->FirstChildElement("FindDisplay");
			if (FindDisplay)
			{
				TiXmlElement* Item = FindDisplay->FirstChildElement("Item");
				while(Item)
				{
					FirewallItem.push_back(Item);
					Item = Item->NextSiblingElement();	
				}
			}
			TiXmlElement* SetRule = Firewall->FirstChildElement("SetRule");
			if (SetRule)
			{
				TiXmlElement* Display = SetRule->FirstChildElement();
				while (Display)
				{
					int set[2];  //0:active   1:action
					CString ID = Display->Attribute("ID");
					CString Active = Display->Attribute("Active");
					CString Action = Display->Attribute("Action");
					if (Active == _T("TRUE"))
					{
						set[0] = 1;
					}
					if (Action == _T("Allow"))
					{
						set[1] = 1;
					}
					SetFirewallRule(set, ID);
					Display = Display->NextSiblingElement();
				}
			}
		}




		TiXmlElement* Environment = root->FirstChildElement("Environment");
		if (Environment != NULL)
		{

			TiXmlElement* DeletePath = Environment->FirstChildElement("DeletePath");
			if (DeletePath)
			{
				TiXmlElement* Path = DeletePath->FirstChildElement("Item");
				while (Path)
				{
					CString NameV = Path->Attribute("Name");
					if (!NameV.IsEmpty())
					{
						DeleteEnvironmentInfo(NameV);
					}
					
					Path = Path->NextSiblingElement();
				}
			}
			TiXmlElement* AddPath = Environment->FirstChildElement("AddPath");
			if (AddPath)
			{
				TiXmlElement* Path = AddPath->FirstChildElement("Item");
				while (Path)
				{
					CString NameV = Path->Attribute("Name");
					if (!NameV.IsEmpty())
					{
						AddEnvironmentInfo(NameV);
					}
					Path = Path->NextSiblingElement();
				}
			}
			TiXmlElement* FindPath = Environment->FirstChildElement("FindPath");
			if (FindPath)
			{
				TiXmlElement* Path = FindPath->FirstChildElement("Item");
				while (Path)
				{
					CString NameV = Path->Attribute("Name");
					EnvironmentItem.push_back(NameV);
					Path = Path->NextSiblingElement();
				}
			}
		}


		TiXmlElement* Software = root->FirstChildElement("Software");
		if (Software != NULL)
		{

			TiXmlElement* FindDisplay = Software->FirstChildElement("FindDisplay");
			if (FindDisplay)
			{
				TiXmlElement* Item = FindDisplay->FirstChildElement("Item");
				while (Item)
				{
					SoftwareItem.push_back(Item);
					Item = Item->NextSiblingElement();
				}
			}
		}



	}
	return true;
}
void GetdiskdriveXml(TiXmlElement *RootElement)
{
	USES_CONVERSION;
	CString appPath = GetAppPath();
	CString seperator = "\\Plugin\\";
	CString fullPath = appPath.GetBuffer(0) + seperator + _T("diskdriveInfo.xml");

	std::string s = T2A(fullPath);
	std::vector<std::wstring> vec_lines;
	UTF16FileRead(s, vec_lines);



	std::wstring ws;
	for (unsigned i = 0; i < vec_lines.size();++i)
	{
		ws = ws+vec_lines.at(i);
	}


	CString Model, MediaType,InterfaceType, Signature, Size;
	CString www = ws.c_str();
	rapidxml::xml_document<> doc;
	doc.parse<0>(T2A(www));
	//! 获取根节点
	rapidxml::xml_node<>* root = doc.first_node();
	CString t3 = root->name();
	//! 获取根节点第一个节点
	rapidxml::xml_node<>* RESULTS = root->first_node("RESULTS");
	if (RESULTS)
	{
		rapidxml::xml_node<>* CIM = RESULTS->first_node("CIM");
		if (CIM)
		{
			rapidxml::xml_node<>* INSTANCE = CIM->first_node("INSTANCE");
			while (INSTANCE)
			{
				TiXmlElement* Disk = new TiXmlElement("DiskItem");
				RootElement->LinkEndChild(Disk);
				rapidxml::xml_node<>* PROPERTY = INSTANCE->first_node("PROPERTY");
				while (PROPERTY)
				{
					rapidxml::xml_attribute<>* Name = PROPERTY->first_attribute("NAME");
					CString name = Name->value();
					if (name == _T("MediaType"))
					{
						rapidxml::xml_node<>* VALUE = PROPERTY->first_node("VALUE");
						if (VALUE)
						{
							MediaType = VALUE->value();
							Disk->SetAttribute("MediaType", T2A(MediaType));
						}
					}
					if (name == _T("Model"))
					{
						rapidxml::xml_node<>* VALUE = PROPERTY->first_node("VALUE");
						if (VALUE)
						{
							Model = VALUE->value();
							Disk->SetAttribute("Name", T2A(Model));
						}
					}
					if (name == _T("InterfaceType"))
					{
						rapidxml::xml_node<>* VALUE = PROPERTY->first_node("VALUE");
						if (VALUE)
						{
							InterfaceType = VALUE->value();
							Disk->SetAttribute("InterfaceType", T2A(InterfaceType));
						}
					}
					if (name == _T("Signature"))
					{
						rapidxml::xml_node<>* VALUE = PROPERTY->first_node("VALUE");
						if (VALUE)
						{
							Signature = VALUE->value();
							Disk->SetAttribute("Signature", T2A(Signature));
							GetDiskInfo(Disk, Signature);
						}
					}
					if (name == _T("Size"))
					{
						rapidxml::xml_node<>* VALUE = PROPERTY->first_node("VALUE");
						if (VALUE)
						{
							Size = VALUE->value();
							int s = _ttof(Size)/1024/1024;
							Size.Format(_T("%d MB"), s);
							Disk->SetAttribute("Size", T2A(Size));
						}
					}
					PROPERTY = PROPERTY->next_sibling();
				}
				INSTANCE = INSTANCE->next_sibling();
			}
		}
	}
}
void GetGPUInfo(TiXmlElement *RootElement)
{
	USES_CONVERSION;
	CString appPath = GetAppPath();
	CString seperator = "\\Plugin\\";
	CString fullPath = appPath.GetBuffer(0) + seperator + _T("gpuz_dump.xml");
	TiXmlDocument *doc = new TiXmlDocument(T2A(fullPath));
	bool loadOkay = doc->LoadFile();
	while (!loadOkay)
	{
		loadOkay = doc->LoadFile();
	}
	TiXmlElement* root = doc->FirstChildElement();
	if (root)
	{
		TiXmlElement tt = *root;	
		RootElement->InsertEndChild(tt);
	}
}
	
bool CreateXmlFile(CString& szFileName)
{//创建xml文件,szFilePath为文件保存的路径,若创建成功返回true,否则false
	try
	{
		USES_CONVERSION;
		TiXmlDocument *myDocument = new TiXmlDocument();
		//创建一个根元素并连接。
		TiXmlElement *RootElement = new TiXmlElement("SystemEnvironment");
		myDocument->LinkEndChild(RootElement);



		TiXmlElement *WindowsVersion = new TiXmlElement("WindowsVersion");
		RootElement->LinkEndChild(WindowsVersion);
		CString ProductName = GetInfo(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), _T("ProductName"), REG_SZ);
		WindowsVersion->SetAttribute("ProductName", T2A(ProductName));



		TiXmlElement *Memory = new TiXmlElement("Memory");
		RootElement->LinkEndChild(Memory);
		GetMemoryInfo(Memory);


		TiXmlElement *Network = new TiXmlElement("Network");
		RootElement->LinkEndChild(Network);
		NetworkCardsInfo(Network);

		TiXmlElement *CPU = new TiXmlElement("CPU");
		RootElement->LinkEndChild(CPU);
		GetCPUInfo(CPU);

		//TiXmlElement *GPU = new TiXmlElement("GPU");
		//RootElement->LinkEndChild(GPU);
		//GetDisplayCardInfo(GPU);
		GetGPUInfo(RootElement);



		TiXmlElement *Disk = new TiXmlElement("Disk");
		RootElement->LinkEndChild(Disk);
		//GetDiskInfo(Disk);
		GetdiskdriveXml(Disk);


		TiXmlElement *Firewall = new TiXmlElement("Firewall");
		RootElement->LinkEndChild(Firewall);
		CString EnableFirewall = GetInfo(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile"), _T("EnableFirewall"), REG_DWORD);
		Firewall->SetAttribute("EnableFirewall", T2A(EnableFirewall));
		GetFirewallRules(Firewall);

		TiXmlElement *Environment = new TiXmlElement("Environment");
		RootElement->LinkEndChild(Environment);
		EnvironmentInfo(Environment);

		TiXmlElement *Software = new TiXmlElement("Software");
		RootElement->LinkEndChild(Software);
		SoftwareInfo(Software);
		

		CString appPath = GetAppPath();
		CString seperator = "\\";
		CString fullPath = appPath.GetBuffer(0) + seperator + szFileName;
		
		const char* path = T2A(fullPath);
		myDocument->SaveFile(path);//保存到文件
	}
	catch (...)
	{
		return false;
	}
	return true;
}



int _tmain(int argc, _TCHAR* argv[])
{
	USES_CONVERSION;

	
	CString Setupxml = _T("Setup.xml");
	CString  savename = _T("save.xml");




	CMyDiskInfo diskinfo;
	diskinfo.GetDiskInfo(1);
	printf("%s,%s", diskinfo.szModelNumber, diskinfo.szSerialNumber);
	getchar();








	CString appPath = GetAppPath();
	CString seperator = "\\Plugin\\";
	CString fullPath = appPath.GetBuffer(0) + seperator + _T("GPU-Z.0.8.5.exe");
//	CString logicaldiskInfoPath = appPath.GetBuffer(0) + seperator + _T("logicaldiskInfo.xml");
	CString diskdriveInfoPath = appPath.GetBuffer(0) + seperator + _T("diskdriveInfo.xml");
	CString cmd = _T("start /b ") + fullPath + _T(" /dump ") + appPath.GetBuffer(0) + seperator + _T("gpuz_dump.xml");
//	CString logicaldiskInfocmd = _T("C:\\WINDOWS\\system32\\wbem\\wmic logicaldisk list full /translate:basicxml /format:rawxml.xsl >") + logicaldiskInfoPath;
	CString diskdriveInfocmd = _T("C:\\WINDOWS\\system32\\wbem\\wmic diskdrive list full  /translate:basicxml /format:rawxml.xsl  >") + diskdriveInfoPath;
	system(T2A(cmd));
//	system(T2A(logicaldiskInfocmd));
	system(T2A(diskdriveInfocmd));
	//CString dd = _T("/dump D:\\zqqzz.xml");
	//ShellExecute(0, _T("open"), fullPath, dd, _T(""), SW_HIDE);
	
	ReadSetupxml(Setupxml);
	CreateXmlFile(savename);
	
	
	return 0;
}