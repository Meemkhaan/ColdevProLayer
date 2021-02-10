#include "stdafx.h" 
//#include "machine_id.h"   

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")


#define WIN32_LEAN_AND_MEAN        
#include <windows.h>      
#include <intrin.h>       
#include <iphlpapi.h>   

#include "base64.h" 
#include "bf_algo.h" 



typedef unsigned int u16;
typedef unsigned long u32;
typedef unsigned long uint32_ty;


typedef struct _AESHeader
{
	int Original_longitud; //evita basura despues del encode64
} AESHeader;







//====================================
#define POLY 0x82f63b78

uint32_ty crc32c(uint32_ty crc, const unsigned char *buf, size_t len)
{
	int k;

	crc = ~crc;
	while (len--) {
		crc ^= *buf++;
		for (k = 0; k < 8; k++)
			crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
	}
	return ~crc;
}



//=============================





//====================================


#define START_ROT47_1 '!'
#define END_ROT47_1 'N'
#define START_ROT47_2 'P'
#if defined _WIN32 || defined _WIN64
#define END_ROT47_2 '}'
#endif
#ifdef unix
#define END_ROT47_2 '~'
#endif



char * MyString(char *s, int decode)
{
    #define base64len (strlen(s)*2)
	char *p = s;
	char *base64;

	//MessageBox(NULL, s, "", MB_OK | MB_ICONEXCLAMATION);

	if (decode)
	{ 
		p = DecodificarBASE64Rapido(s);	
		//MessageBox(NULL, p, "decode", MB_OK | MB_ICONEXCLAMATION);
	}
		
	int case_type, idx, len;

	for (idx = 0, len = strlen(p); idx < len; idx++) {
		// Only process alphabetic characters.
		if (p[idx] < 'A' || (p[idx] > 'Z' && p[idx] < 'a') || p[idx] > 'z')
			continue;
		// Determine if the char is upper or lower case.
		if (p[idx] >= 'a')
			case_type = 'a';
		else
			case_type = 'A';
		// Rotate the char's value, ensuring it doesn't accidentally "fall off" the end.
		p[idx] = (p[idx] + 13) % (case_type + 26);
		if (p[idx] < 26)
			p[idx] += case_type;
	}

	//MessageBox(NULL, p, "", MB_OK | MB_ICONEXCLAMATION);


	if (decode == 0)
	{
		base64 = (char *)emalloc(base64len);
		memset(base64, 0, base64len);

		base64_encode((BYTE *)s, (BYTE *)base64, strlen(s), 1);
		return base64;
	}
	else  //decode 1
	{
		return p;
	}	
}




//====================================



char * EncriptarAES(char *plaintext, int longitud, int *out_longitud, char *key2, int key_len)
{
	WORD2 key_schedule[60], idx;
	AESHeader  aesheader;

	BYTE *enc_buf = (BYTE *)emalloc(longitud);
	memset(enc_buf, 0, longitud);


	BYTE key[1][32] = {
		{ 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }
	};
	BYTE iv[1][16] = {
		{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff },
	};


	if (key_len > 32) key_len = 32;

	memcpy(&key[0], key2, key_len);  //tiene mas de 32 caracteres
	

	aes_key_setup((BYTE*)key[0], key_schedule, 256);

	aes_encrypt_ctr((BYTE*)plaintext, longitud, enc_buf, key_schedule, 256, iv[0]);

	//=====
	aesheader.Original_longitud = longitud;

	char *Mydata = (char*)emalloc(longitud*2);
	memset(Mydata, 0, longitud * 2);

	memcpy(Mydata, &aesheader, sizeof(AESHeader));

	memcpy(Mydata + sizeof(AESHeader), enc_buf, longitud);

#define longitudDATA (longitud + sizeof(AESHeader))

	//=====
	BYTE *base64buff = (BYTE *)emalloc(longitud * 2);
	memset(base64buff, 0, longitud * 2);

	int base64long = base64_encode((BYTE*)Mydata, base64buff, longitudDATA, 1);
	efree(enc_buf);
	efree(Mydata);

	*out_longitud = base64long;

	return (char *)base64buff;
}





char * DesencriptarAES(char *plaintext, int longitud, int *out_longitud, char *key2, int key_len)
{
	WORD2 key_schedule[60], idx;


	BYTE iv[1][16] = {
		{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff },
	};

	BYTE key[1][32] = {
		{ 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 }
	};

	//===
	BYTE *base64buff = (BYTE *)emalloc(longitud);
	int base64long = base64_decode((BYTE *)plaintext, base64buff, longitud);

	*out_longitud = base64long;
	//===


	//aesheader.Original_longitud = longitud;

	AESHeader*header = (AESHeader*)base64buff;

	char *buffersalida =(char*) emalloc(header->Original_longitud);
	memset(buffersalida, 0, header->Original_longitud);

	memcpy(buffersalida, base64buff + sizeof(AESHeader), header->Original_longitud);


	//=======

	BYTE *enc_buf = (BYTE *)emalloc(base64long);
	memset(enc_buf, 0, base64long);

	//===
	if (key_len > 32) key_len = 32;

	memcpy(&key[0], key2, key_len);  //tiene mas de 32 caracteres

	//===
	aes_key_setup((BYTE*)key[0], key_schedule, 256);

	aes_decrypt_ctr((BYTE*)buffersalida, header->Original_longitud, enc_buf, key_schedule, 256, iv[0]);
	efree(base64buff);
	efree(buffersalida);

	return (char *)enc_buf;
}





// we just need this for purposes of unique machine id. So any one or two mac's is       
// fine. 
u16 hashMacAddress(PIP_ADAPTER_INFO info)
{
	u16 hash = 0;
	for (u32 i = 0; i < info->AddressLength; i++)
	{
		hash += (info->Address[i] << ((i & 1) * 8));
	}
	return hash;
}

void getMacHash(u16& mac1, u16& mac2)
{
	IP_ADAPTER_INFO AdapterInfo[32];
	DWORD dwBufLen = sizeof(AdapterInfo);

	DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
	if (dwStatus != ERROR_SUCCESS)
		return; // no adapters.      

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
	mac1 = hashMacAddress(pAdapterInfo);
	if (pAdapterInfo->Next)
		mac2 = hashMacAddress(pAdapterInfo->Next);

	// sort the mac addresses. We don't want to invalidate     
	// both macs if they just change order.           
	if (mac1 > mac2)
	{
		u16 tmp = mac2;
		mac2 = mac1;
		mac1 = tmp;
	}
}

u16 getVolumeHash()
{
	DWORD serialNum = 0;

	//"c:\\"
	char *mensaje1 = DecodificarBASE64Rapido("Yzpc");

	// Determine if this volume uses an NTFS file system.      
	GetVolumeInformation(mensaje1, NULL, 0, &serialNum, NULL, NULL, NULL, 0);
	efree(mensaje1);

	u16 hash = (u16)((serialNum + (serialNum >> 16)) & 0xFFFF);

	return hash;
}

u16 getCpuHash()
{
	int cpuinfo[4] = { 0, 0, 0, 0 };
	__cpuid(cpuinfo, 0);
	u16 hash = 0;
	
	for (u32 i = 0; i < 4; i++)
		hash += cpuinfo[i];

	return hash;
}

const char* getMachineName()
{
	static char computerName[1024];
	DWORD size = 1024;
	GetComputerName(computerName, &size);
	return &(computerName[0]);
}










// ==================================================================




int MainBoardInfo(char *infoBios, char *infoPCMachine)
{
	HKEY hKey = 0;
	char buf[MAX_PATH];
	DWORD dwType = 0;
	DWORD dwBufSize = MAX_PATH;
	LONG result;
	
	 char   HKEYBIOS[] = "VU5FUUpORVJcUVJGUEVWQ0dWQkFcRmxmZ3J6XE9WQkY=";//"HARDWARE\\DESCRIPTION\\System\\BIOS";
	 char   HKEYBIOSDATE[] = "T1ZCRkVyeXJuZnJRbmdy";//"BIOSReleaseDate";
	 char   HKEYproductname[] = "RmxmZ3J6Q2VicWhwZ0FuenI=";//"SystemProductName";

	
	char *Hkeybios = MyString(HKEYBIOS, 1);
	char *Hkeybiosdate = MyString(HKEYBIOSDATE, 1);
	char *Hkeyproductname = MyString(HKEYproductname, 1);

	
	
//	MessageBox(NULL, Hkeybiosdate,		Hkeybios, MB_OK | MB_ICONEXCLAMATION);

	result = 0;
	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, Hkeybios, 0, KEY_QUERY_VALUE, &hKey);
	if (result == ERROR_SUCCESS)
	{
		dwType = REG_SZ;
		result = RegQueryValueEx(hKey, Hkeybiosdate, NULL, &dwType, (BYTE*)buf, &dwBufSize);
		if (result == ERROR_SUCCESS)
		{
			strcpy_s(infoBios, dwBufSize, buf);	

		}	
		RegCloseKey(hKey);
	}//end if


	 hKey = 0;
	 dwType = 0;
	 dwBufSize = MAX_PATH;

	 result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, Hkeybios, 0, KEY_QUERY_VALUE, &hKey);
	if (result == ERROR_SUCCESS)
	{
		dwType = REG_SZ;
		result = RegQueryValueEx(hKey, Hkeyproductname, NULL, &dwType, (BYTE*)buf, &dwBufSize);
		if (result == ERROR_SUCCESS)
		{
			strcpy_s(infoPCMachine, dwBufSize, buf);
			
		}		
		RegCloseKey(hKey);
	}//end if

	efree( Hkeybios);
	efree( Hkeybiosdate);
	efree( Hkeyproductname);
	
	return 0;
}//end function 



char *GetMyhardwareID()
{
	char * main_key = ObtenerLLavePpal();

	char mybios[30] = "";
	char mypc[100] = "";
	char macAddress[50] = "";
	char VolumeSerial[50] = "";
	u16 mac1, mac2, volume, myCpu;

	char *buffer = (char *)emalloc(250);
	memset(buffer, 0, 250);

	volume = getVolumeHash();
	myCpu = getCpuHash();

	MainBoardInfo(mybios, mypc);
	getMacHash(mac1, mac2);

	//"%d, %d"
	char *mensaje1 = DecodificarBASE64Rapido("JWQsICVk");

	sprintf_s(macAddress, 40, mensaje1, mac1, mac2);
	sprintf_s(VolumeSerial, 40, mensaje1, volume, myCpu);
	efree(mensaje1);


	strcpy_s(buffer, 250, "{");
	strcat_s(buffer, 250, macAddress);
	strcat_s(buffer, 250, "} ");

	strcat_s(buffer, 250, "[");
	strcat_s(buffer, 250, VolumeSerial);
	strcat_s(buffer, 250, "]");

	strcat_s(buffer, 250, "(");
	strcat_s(buffer, 250, mybios);
	strcat_s(buffer, 250, ",");
	strcat_s(buffer, 250, mypc);
	strcat_s(buffer, 250, ")");

	
	int buffer_aes_len;
	char *Buffer64 = EncriptarAES(buffer, strlen(buffer), &buffer_aes_len, main_key, strlen(main_key));

	efree(buffer);
	efree(main_key);
	
	return Buffer64;
	
}




char * DecodificarBASE64Rapido(char *mensajeoculto)
{	
	int longitud = strlen(mensajeoculto);
	char *b64data = (char *)emalloc(longitud);
	memset(b64data, 0, longitud);

	base64_decode((const BYTE *)mensajeoculto, (BYTE *)b64data, longitud);
	
	return b64data;
}



//double rot13 + base64
char *MyStringDouble(char *cadenaescondida, int decode)
{	
	char * cadena1 = MyString(cadenaescondida, decode);
	char * cadena2 = MyString(cadena1, decode);
	efree(cadena1);

	return cadena2;
}




// ---------------------------------------------------



//llave ppal 
char *ObtenerLLavePpal()
{
	int main_key_encoded_alloc_len = strlen(main_key_encoded);

	char * main_key_encoded_alloc = (char*)emalloc(main_key_encoded_alloc_len + 1); //la cadena tiene final 0 entonces+1
	memset(main_key_encoded_alloc, 0, main_key_encoded_alloc_len + 1);

	memcpy(main_key_encoded_alloc, main_key_encoded, main_key_encoded_alloc_len);

	char *millave = MyStringDouble(main_key_encoded_alloc, 1);
	efree(main_key_encoded_alloc);

	return millave;
}









//========================================================

#include <winsock2.h>
#include <windows.h>


int ConectarServidor(){
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
//		cout << "WSAStartup failed.\n";
		system("pause");
		return 1;
	}
	SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct hostent *host;
	host = gethostbyname("www.google.com");
	SOCKADDR_IN SockAddr;
	SockAddr.sin_port = htons(80);
	SockAddr.sin_family = AF_INET;
	SockAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr);
//	cout << "Connecting...\n";
	if (connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr)) != 0){
	//	cout << "Could not connect";
		//system("pause");
		return 1;
	}
//	cout << "Connected.\n";
	send(Socket, "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n", strlen("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"), 0);
	char buffer[10000];
	int nDataLength;
	while ((nDataLength = recv(Socket, buffer, 10000, 0)) > 0){
		int i = 0;
		while (buffer[i] >= 32 || buffer[i] == '\n' || buffer[i] == '\r') {
		//	cout << buffer[i];
			i += 1;
		}
	}

	closesocket(Socket);
	WSACleanup();
	//system("pause");
	return 0;
}