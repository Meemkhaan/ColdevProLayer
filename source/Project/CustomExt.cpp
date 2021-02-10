/*
The MIT License

Copyright Colombian Developers 2021

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include "stdafx.h"
#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#if PHP_MAJOR_VERSION < 7
 #include "ext/standard/php_smart_str.h"
#else
 #include "ext/standard/php_smart_string.h" 
#endif

#include "ext/standard/md5.h"
#include "ext/standard/base64.h"

#ifndef ENFORCE_SAFE_MODE
  #define ENFORCE_SAFE_MODE 0
#endif

#include "base64.h" 
#include "sha256.h" 
#include "bf_algo.h"

char * MyString(char *s, int decode);

typedef unsigned char b_byte;
typedef unsigned int  b_uint;
typedef unsigned long uint32_ty;


#define ColdevProLayer_BUFSIZE 4092
#define HASH_MY_LEN 65

#define ColdevProLayer_IDENT "ColdevLayer"
#define PHP_ColdevProLayer_VERSION "1.06.0"
#define PHP_ColdevProLayer_VERSION_STEALTH 1060


typedef struct _ColdevProLayer_LicHeader
{
	b_byte Ident[20];
	b_byte Md5[HASH_MY_LEN];
	b_byte DateExpires[12];
	b_byte Company[50];
	b_byte Host[50];
	b_byte IdHardware[255];
	b_byte Hash2file[200];
	uint32_ty Crc; //integ file1
	uint32_ty Crc_len;
	b_byte LinuxCreate[2];

} ColdevProLayer_LicHeader;


typedef struct _ColdevProLayer_header
{
	b_byte Ident[20];
	b_byte Version[8];
	int Stealth;  //oculta ID
	int Stealth_Version; //version del oculto
	b_byte Md5[HASH_MY_LEN*2];  //se guarda encoded
	b_byte Metadata[120];  //encript pass licence - hash
	b_byte Hash1file[200];
	uint32_ty Crc;//integ file2

} ColdevProLayer_header;






ZEND_BEGIN_MODULE_GLOBALS(ColdevProLayer)
char *key_file;
char *decoded;
unsigned int decoded_len;
unsigned int index;
zend_bool keys_loaded;
zend_bool expired;
char *expire_date;
unsigned long expire_date_numerical;
ZEND_END_MODULE_GLOBALS(ColdevProLayer)


ZEND_DECLARE_MODULE_GLOBALS(ColdevProLayer)



/* declaration of functions to be exported */
ZEND_FUNCTION(GET_SERIAL_ID_CPL);
ZEND_FUNCTION(GloryFunc);

ZEND_FUNCTION(ColdevProLayer_encrypt);

PHP_MINIT_FUNCTION(ColdevProLayer);
PHP_MSHUTDOWN_FUNCTION(ColdevProLayer);
PHP_RINIT_FUNCTION(ColdevProLayer);
PHP_MINFO_FUNCTION(ColdevProLayer);

#if PHP_MAJOR_VERSION <= 7
  #define CABECERA_PHP_FINAL  TSRMLS_DC
#else
  #define CABECERA_PHP_FINAL  
#endif

size_t(*old_stream_reader)(void *, char *, size_t TSRMLS_DC);
void(*old_stream_closer)(void * TSRMLS_DC);

zend_op_array* (*zend_compile_file_old)(zend_file_handle*, int TSRMLS_DC);
zend_op_array* ColdevProLayer_compile(zend_file_handle*, int TSRMLS_DC);

#if PHP_MAJOR_VERSION <= 7
	static zend_op_array *(*orig_compile_string)(zval *source_string, char *filename CABECERA_PHP_FINAL);
	static zend_op_array *evalhook_compile_string(zval *source_string, char *filename CABECERA_PHP_FINAL);
#else
	static zend_op_array* (*orig_compile_string)(zend_string* source_string,const char* filename CABECERA_PHP_FINAL);
	static zend_op_array* evalhook_compile_string(zend_string* source_string,const char* filename CABECERA_PHP_FINAL);
#endif

b_byte *php_ColdevProLayer_decode(void *input, unsigned char *key, int in_len, int *out_len CABECERA_PHP_FINAL);
b_byte *php_ColdevProLayer_encode(void *script, unsigned char *key, int in_len, int *out_len CABECERA_PHP_FINAL);

#if PHP_VERSION_ID >= 70000
void(*xdebug_old_execute_ex)(zend_execute_data *execute_data CABECERA_PHP_FINAL);
void xdebug_execute_ex(zend_execute_data *execute_data CABECERA_PHP_FINAL);

void(*xdebug_old_execute_internal)(zend_execute_data *current_execute_data, zval *return_value);
void xdebug_execute_internal(zend_execute_data *current_execute_data, zval *return_value);
#elif PHP_VERSION_ID >= 50500
void(*xdebug_old_execute_ex)(zend_execute_data *execute_data TSRMLS_DC);
void xdebug_execute_ex(zend_execute_data *execute_data TSRMLS_DC);

void(*xdebug_old_execute_internal)(zend_execute_data *current_execute_data, struct _zend_fcall_info *fci, int return_value_used TSRMLS_DC);
void xdebug_execute_internal(zend_execute_data *current_execute_data, struct _zend_fcall_info *fci, int return_value_used TSRMLS_DC);
#else
void(*xdebug_old_execute)(zend_op_array *op_array TSRMLS_DC);
void xdebug_execute(zend_op_array *op_array TSRMLS_DC);

void(*xdebug_old_execute_internal)(zend_execute_data *current_execute_data, int return_value_used TSRMLS_DC);
void xdebug_execute_internal(zend_execute_data *current_execute_data, int return_value_used TSRMLS_DC);
#endif



char *GetMyhardwareID();

uint32_ty crc32c(uint32_ty crc, const unsigned char *buf, size_t len);


/* compiled function list so Zend knows what's in this module */
zend_function_entry ColdevProLayer_functions[] = {
	ZEND_FE(GET_SERIAL_ID_CPL, NULL)
	ZEND_FE(GloryFunc, NULL)
	PHP_FE(ColdevProLayer_encrypt, NULL)
	{
		NULL, NULL, NULL
	}
};

/* compiled module information */
zend_module_entry ColdevProLayer_module_entry = {
	STANDARD_MODULE_HEADER,
	"ColdevProLayer Module",
	ColdevProLayer_functions,
	PHP_MINIT(ColdevProLayer),
	PHP_MSHUTDOWN(ColdevProLayer),
	PHP_RINIT(ColdevProLayer),
	NULL, 
	PHP_MINFO(ColdevProLayer),
	PHP_ColdevProLayer_VERSION, STANDARD_MODULE_PROPERTIES
};

/* implement standard "stub" routine to introduce ourselves to Zend */
ZEND_GET_MODULE(ColdevProLayer)



//anti debug
#if PHP_VERSION_ID >= 70000
void xdebug_execute_ex(zend_execute_data *execute_data CABECERA_PHP_FINAL)
{
#elif PHP_VERSION_ID >= 50500
void xdebug_execute_ex(zend_execute_data *execute_data TSRMLS_DC)
{
#else
void xdebug_execute(zend_op_array *op_array TSRMLS_DC)
{
#endif


#if PHP_VERSION_ID < 50500
	xdebug_old_execute(op_array TSRMLS_CC);
#else
	xdebug_old_execute_ex(execute_data CABECERA_PHP_FINAL);
#endif

	return;
}



//anti debug
#if PHP_VERSION_ID >= 70000
void xdebug_execute_internal(zend_execute_data *current_execute_data, zval *return_value)
#elif PHP_VERSION_ID >= 50500
void xdebug_execute_internal(zend_execute_data *current_execute_data, struct _zend_fcall_info *fci, int return_value_used TSRMLS_DC)
#else
void xdebug_execute_internal(zend_execute_data *current_execute_data, int return_value_used TSRMLS_DC)
#endif
{
    
#if PHP_VERSION_ID >= 70000
			xdebug_old_execute_internal(current_execute_data, return_value CABECERA_PHP_FINAL);
#elif PHP_VERSION_ID >= 50500
			xdebug_old_execute_internal(current_execute_data, fci, return_value_used TSRMLS_CC);
#else
			xdebug_old_execute_internal(current_execute_data, return_value_used TSRMLS_CC);
#endif


	return;
}





/* {{{ PHP_INI 
PHP_INI_BEGIN()
STD_PHP_INI_ENTRY("public.key_file", "/usr/local/etc/publickeys", PHP_INI_ALL, OnUpdateString, key_file, zend_ColdevProLayer_globals, ColdevProLayer_globals)
PHP_INI_END()
/* }}} */


// =========================================

static void php_ColdevProLayer_init_globals(zend_ColdevProLayer_globals *ColdevProLayer_globals)
{


}



/* {{{ PHP_MINIT_FUNCTION
*/
PHP_MINIT_FUNCTION(ColdevProLayer)
{
//	ZEND_INIT_MODULE_GLOBALS(ColdevProLayer, php_ColdevProLayer_init_globals, NULL);
	//REGISTER_INI_ENTRIES();

	
	REGISTER_STRING_CONSTANT("ColdevProLayer_EXT_VERSION", PHP_ColdevProLayer_VERSION, CONST_CS | CONST_PERSISTENT);
	
	zend_compile_file_old = zend_compile_file;
	zend_compile_file = ColdevProLayer_compile;
    
	orig_compile_string = zend_compile_string;
	zend_compile_string = evalhook_compile_string;


	//anti debug
#if PHP_VERSION_ID < 50500
	xdebug_old_execute = zend_execute;
	zend_execute = xdebug_execute;
#else
	xdebug_old_execute_ex = zend_execute_ex;
	zend_execute_ex = xdebug_execute_ex;
#endif

	return SUCCESS;
}


PHP_MSHUTDOWN_FUNCTION(ColdevProLayer)
{
	//UNREGISTER_INI_ENTRIES();

	zend_compile_string = orig_compile_string;
	zend_compile_file = zend_compile_file_old;

	//antidebug
#if PHP_VERSION_ID < 50500
	zend_execute = xdebug_old_execute;
#else
	zend_execute_ex = xdebug_old_execute_ex;
#endif

	return SUCCESS;
}



/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
*/
PHP_RINIT_FUNCTION(ColdevProLayer)
{

	return SUCCESS;
}
/* }}} */




/* {{{ PHP_MINFO_FUNCTION
*/
typedef unsigned int u16;
int MainBoardInfo(char *infoBios, char *infoPCMachine);
void getMacHash(u16& mac1, u16& mac2);
u16 getVolumeHash();
u16 getCpuHash();

PHP_MINFO_FUNCTION(ColdevProLayer)
{
	php_info_print_table_start();

	    //"ColdevProLayer By "
 	    char *mensaje1 = DecodificarBASE64Rapido("Q29sZGV2UHJvTGF5ZXIgQnkg");
		//"Colombian Developers"
		char *mensaje2 = DecodificarBASE64Rapido("Q29sb21iaWFuIERldmVsb3BlcnM=");
		php_info_print_table_row(2, mensaje1,mensaje2 );
		efree(mensaje1);
		efree(mensaje2);

		//"ColdevProLayer Elliptic Curve Cryptography"
		mensaje1 = DecodificarBASE64Rapido("Q29sZGV2UHJvTGF5ZXIgRWxsaXB0aWMgQ3VydmUgQ3J5cHRvZ3JhcGh5");
		//"Enabled"
		mensaje2 = DecodificarBASE64Rapido("RW5hYmxlZA==");
		php_info_print_table_row(2, mensaje1, mensaje2);
		efree(mensaje1);
		efree(mensaje2);

		//""ColdevProLayer version""
		mensaje1 = DecodificarBASE64Rapido("Q29sZGV2UHJvTGF5ZXIgdmVyc2lvbg==");
		php_info_print_table_row(2, mensaje1, PHP_ColdevProLayer_VERSION);
		efree(mensaje1);
		
		//"ColdevProLayer Build Date "
		mensaje1 = DecodificarBASE64Rapido("Q29sZGV2UHJvTGF5ZXIgQnVpbGQgRGF0ZSA=");
		php_info_print_table_row(2, mensaje1, __DATE__ " " __TIME__);
		efree(mensaje1);
		

	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}
/* }}} */




ZEND_FUNCTION(GloryFunc)
{
	const char OurLord1[] = "T3VyIEZhdGhlciwgDQp3aG8gYXJ0IGluIEhlYXZlbiwgDQpoYWxsb3dlZCBieSBUaHkgbmFtZSwgDQpUaHkga2luZ2RvbSBjb21lLCANClRoeSB3aWxsIGJlIGRvbmUgDQpvbiBlYXJ0aCBhcyBpdCBpcyBpbiBIZWF2ZW4uIA0KDQpHaXZlIHVzIHRoaXMgZGF5IG91ciBkYWlseSBicmVhZCwgDQphbmQgZm9yZ2l2ZSB1cyBvdXIgdHJlc3Bhc3NlcyANCmFzIHdlIGZvcmdpdmUgdGhvc2Ugd2hvIHRyZXNwYXNzIGFnYWluc3QgdXMuIA0KQW5kIGxlYWQgdXMgbm90IGludG8gdGVtcHRhdGlvbiANCmJ1dCBkZWxpdmVyIHVzIGZyb20gZXZpbC4g";
	const char OurLord2[] = "UGF0ZXIgbm9zdGVyLCBxdWkgZXMgaW4gY2FlbGlzLA0Kc2FuY3RpZmljZXR1ciBub21lbiB0dXVtLA0KYWR2ZW5pYXQgcmVnbnVtIHR1dW0sDQpmaWF0IHZvbHVudGFzIHR1YSwNCnNpY3V0IGluIGNhZWxvLCBldCBpbiB0ZXJyYS4NClBhbmVtIG5vc3RydW0gc3VwZXJzdWJzdGFudGlhbGVtIGRhIG5vYmlzIGhvZGllOw0KZXQgZGltaXR0ZSBub2JpcyBkZWJpdGEgbm9zdHJhLA0Kc2ljdXQgZXQgbm9zIGRpbWl0dGltdXMgZGViaXRvcmlidXMgbm9zdHJpczsNCmV0IG5lIGluZHVjYXMgbm9zIGluIHRlbnRhdGlvbmVtOw0Kc2VkIGxpYmVyYSBub3MgYSBNYWxvLg==";
	const char OurLord3[] = "T3VyIEZhdGhlciwgDQp3aG8gYXJ0IGluIEhlYXZlbiwgDQpoYWxsb3dlZCBieSBUaHkgbmFtZSwgDQpUaHkga2luZ2RvbSBjb21lLCANClRoeSB3aWxsIGJlIGRvbmUgDQpvbiBlYXJ0aCBhcyBpdCBpcyBpbiBIZWF2ZW4uIA0KDQpHaXZlIHVzIHRoaXMgZGF5IG91ciBkYWlseSBicmVhZCwgDQphbmQgZm9yZ2l2ZSB1cyBvdXIgdHJlc3Bhc3NlcyANCmFzIHdlIGZvcmdpdmUgdGhvc2Ugd2hvIHRyZXNwYXNzIGFnYWluc3QgdXMuIA0KQW5kIGxlYWQgdXMgbm90IGludG8gdGVtcHRhdGlvbiANCmJ1dCBkZWxpdmVyIHVzIGZyb20gZXZpbC4g";
	const char OurLord4[] = "UGF0ZXIgbm9zdGVyLCBxdWkgZXMgaW4gY2FlbGlzLA0Kc2FuY3RpZmljZXR1ciBub21lbiB0dXVtLA0KYWR2ZW5pYXQgcmVnbnVtIHR1dW0sDQpmaWF0IHZvbHVudGFzIHR1YSwNCnNpY3V0IGluIGNhZWxvLCBldCBpbiB0ZXJyYS4NClBhbmVtIG5vc3RydW0gc3VwZXJzdWJzdGFudGlhbGVtIGRhIG5vYmlzIGhvZGllOw0KZXQgZGltaXR0ZSBub2JpcyBkZWJpdGEgbm9zdHJhLA0Kc2ljdXQgZXQgbm9zIGRpbWl0dGltdXMgZGViaXRvcmlidXMgbm9zdHJpczsNCmV0IG5lIGluZHVjYXMgbm9zIGluIHRlbnRhdGlvbmVtOw0Kc2VkIGxpYmVyYSBub3MgYSBNYWxvLg==";
	const char OurLord5[] = "T3VyIEZhdGhlciwgDQp3aG8gYXJ0IGluIEhlYXZlbiwgDQpoYWxsb3dlZCBieSBUaHkgbmFtZSwgDQpUaHkga2luZ2RvbSBjb21lLCANClRoeSB3aWxsIGJlIGRvbmUgDQpvbiBlYXJ0aCBhcyBpdCBpcyBpbiBIZWF2ZW4uIA0KDQpHaXZlIHVzIHRoaXMgZGF5IG91ciBkYWlseSBicmVhZCwgDQphbmQgZm9yZ2l2ZSB1cyBvdXIgdHJlc3Bhc3NlcyANCmFzIHdlIGZvcmdpdmUgdGhvc2Ugd2hvIHRyZXNwYXNzIGFnYWluc3QgdXMuIA0KQW5kIGxlYWQgdXMgbm90IGludG8gdGVtcHRhdGlvbiANCmJ1dCBkZWxpdmVyIHVzIGZyb20gZXZpbC4g";
	const char OurLord6[] = "UGF0ZXIgbm9zdGVyLCBxdWkgZXMgaW4gY2FlbGlzLA0Kc2FuY3RpZmljZXR1ciBub21lbiB0dXVtLA0KYWR2ZW5pYXQgcmVnbnVtIHR1dW0sDQpmaWF0IHZvbHVudGFzIHR1YSwNCnNpY3V0IGluIGNhZWxvLCBldCBpbiB0ZXJyYS4NClBhbmVtIG5vc3RydW0gc3VwZXJzdWJzdGFudGlhbGVtIGRhIG5vYmlzIGhvZGllOw0KZXQgZGltaXR0ZSBub2JpcyBkZWJpdGEgbm9zdHJhLA0Kc2ljdXQgZXQgbm9zIGRpbWl0dGltdXMgZGViaXRvcmlidXMgbm9zdHJpczsNCmV0IG5lIGluZHVjYXMgbm9zIGluIHRlbnRhdGlvbmVtOw0Kc2VkIGxpYmVyYSBub3MgYSBNYWxvLg==";

	MessageBox(NULL, OurLord1, OurLord2, MB_OK | MB_ICONEXCLAMATION);
	MessageBox(NULL, OurLord3, OurLord4, MB_OK | MB_ICONEXCLAMATION);
	MessageBox(NULL, OurLord5, OurLord6, MB_OK | MB_ICONEXCLAMATION);


	RETURN_STRING("God is Love", true);

}


/* H ID */
/* GET UNIQUE HARDWARE ID BY COLOMBIAN DEVELOPERS */
ZEND_FUNCTION(GET_SERIAL_ID_CPL)
{
	char *Buffer64=  GetMyhardwareID();


	RETURN_STRING(Buffer64, true);
}






#if PHP_MAJOR_VERSION <= 7
static zend_op_array *evalhook_compile_string(zval *source_string, char *filename CABECERA_PHP_FINAL)
#else
static zend_op_array* evalhook_compile_string(zend_string* source_string, const char* filename CABECERA_PHP_FINAL)
#endif
{ 
		return orig_compile_string(source_string, filename CABECERA_PHP_FINAL); 
}





int ReadLicenseFile(char *NombreArchivo,char * HostLimits,char *MD5hash, char *hash1file, uint32_ty CRCLicenciafile2, uint32_ty *CrcCodefile1, int *CrcCodefile1_len, char *dateexpires, char *appserial, char *companyname  CABECERA_PHP_FINAL)
{
	int i = 0, res = 0;
	size_t bytes;
	php_stream *stream;
	char *script = NULL;
	b_byte *decoded = NULL;
	unsigned int decoded_len = 0;
	unsigned int index = 0;
	unsigned int script_len = 0;
	zend_op_array *retval = NULL;
	ColdevProLayer_LicHeader  *header;
	char *mensaje;

	if ((stream = php_stream_open_wrapper(NombreArchivo, "r", ENFORCE_SAFE_MODE | REPORT_ERRORS, NULL)) == NULL) {
		//licence open error
		mensaje = DecodificarBASE64Rapido("Q29sZGV2TGF5ZXI6IExpY2Vuc2UgZmlsZSBvcGVuIGVycm9yLg==");
		zend_error(E_ERROR, mensaje);
		
		return 0;
	}

	script = (char *)emalloc(ColdevProLayer_BUFSIZE);
	for (i = 2; (bytes = php_stream_read(stream, &script[index], ColdevProLayer_BUFSIZE)) > 0; i++)
	{
		script_len += bytes;
		if (bytes == ColdevProLayer_BUFSIZE)
		{
			script = (char *)erealloc(script, ColdevProLayer_BUFSIZE * i);
			index += bytes;

		}
	}

	script_len += bytes;

	php_stream_close(stream);

	if (!script_len) 
	{
		//licence open error
		mensaje = DecodificarBASE64Rapido("Q29sZGV2TGF5ZXI6IExpY2Vuc2UgZmlsZSBvcGVuIGVycm9yLg==");

		zend_error(E_ERROR, mensaje);
		return 0;
	}

	//calcula CRC de la licencia y compara
	uint32_ty CrcCodigocompara = crc32c(0, (unsigned char*)script, script_len);//calcula integridad y la compara

	if (CrcCodigocompara != CRCLicenciafile2)
	{
		//licence corrupt
		mensaje = DecodificarBASE64Rapido("Q29sZGV2TGF5ZXI6IExpY2Vuc2UgY29ycnVwdC4=");
		zend_error(E_ERROR, mensaje);
		return 0;
	}

    //======
	int longitud_licencia;
	char *licencia = DesencriptarAES(script, script_len, &longitud_licencia, hash1file, strlen(hash1file));
	

	header = (ColdevProLayer_LicHeader*)licencia;

	if (strncmp((char*)header->Ident, ColdevProLayer_IDENT, strlen(ColdevProLayer_IDENT))  != 0 )//verifica que el cifrado OK
	{
		//"ColdevLayer: Invalid License. CRC"
		mensaje = DecodificarBASE64Rapido("Q29sZGV2TGF5ZXI6IEludmFsaWQgTGljZW5zZS4gQ1JD");
		zend_error(E_ERROR, mensaje);
		return 0;
	}

	strcpy_s(MD5hash, HASH_MY_LEN, (char*)header->Md5); //copia la hash clave

	if (strlen((char*)header->DateExpires) == 8)//verifica la fecha de expiracion
	{
		time_t t = time(NULL);
		struct tm tm = *localtime(&t);
		char fechaHoy[10];
		sprintf(fechaHoy, "%d%02d%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
		
		if ( atoi(fechaHoy) > atoi((char*)header->DateExpires))  //yyyymmdd
		{
			//"ColdevLayer: License expires. "
			mensaje = DecodificarBASE64Rapido("Q29sZGV2TGF5ZXI6IExpY2Vuc2UgZXhwaXJlcy4g");
			zend_error(E_ERROR, mensaje);
			return 0;
		}

		memcpy(dateexpires,  (char*)header->DateExpires, 8);
	}


	if (strlen((char*)header->IdHardware) > 0)//verifica el hardwareID
	{
		char *HardID= GetMyhardwareID();

		if (strncmp((char*)header->IdHardware, HardID, strlen(HardID)) != 0)//es el mismo HARDWARE ?
		{
			//"(        ColdevLayer: Invalid License Id. Please contact your provider with this ID: %s         )"
			mensaje = DecodificarBASE64Rapido("KCAgICAgICAgQ29sZGV2TGF5ZXI6IEludmFsaWQgTGljZW5zZSBJZC4gUGxlYXNlIGNvbnRhY3QgeW91ciBwcm92aWRlciB3aXRoIHRoaXMgSUQ6ICVzICAgICAgICAgKQ==");
			zend_error(E_ERROR, mensaje , HardID);
			return 0;
		}
		efree(HardID);

		memcpy(appserial, (char*)header->IdHardware,strlen((char*)header->IdHardware));
	}

	*CrcCodefile1 = header->Crc;   //integridad file1
	*CrcCodefile1_len = header->Crc_len;


	if (strlen((char*)header->Host)>0) //hostlimits
	{ 
	   memcpy(HostLimits, (char*) header->Host, strlen((char*)header->Host));
	}


	if (strlen((char*)header->Company)>0) //company name
	{
		memcpy(companyname,  (char*)header->Company,strlen((char*)header->Company));
	}


	efree(licencia);
	efree(script);


	return 1;
}







zend_op_array *ColdevProLayer_compile(zend_file_handle *file_handle, int type CABECERA_PHP_FINAL)
{
	int i = 0, res = 0;
	size_t bytes;
	php_stream *stream;
	char *script = NULL;
	b_byte *decoded = NULL;
	unsigned int decoded_len = 0;
	unsigned int index = 0;
	unsigned int script_len = 0;
	zend_op_array *retval = NULL;
	ColdevProLayer_header  *header;	
	zend_bool validated = FALSE;
	char * main_key = ObtenerLLavePpal();

#if PHP_MAJOR_VERSION < 7
	zval *code;
	MAKE_STD_ZVAL(code);
#else
 	zval code;
#endif

	
	char *mensajeError;
	

	/*
	* using php_stream instead zend internals
	*/
	if ((stream = php_stream_open_wrapper((char *)file_handle->filename, "r", ENFORCE_SAFE_MODE | REPORT_ERRORS, NULL)) == NULL) {
		//"ColdevLayer: unable to open stream, compiling with default compiler."
		mensajeError = DecodificarBASE64Rapido("IkNvbGRldkxheWVyOiB1bmFibGUgdG8gb3BlbiBzdHJlYW0sIGNvbXBpbGluZyB3aXRoIGRlZmF1bHQgY29tcGlsZXIuIg==");
		zend_error(E_NOTICE, mensajeError);

		return retval = zend_compile_file_old(file_handle, type CABECERA_PHP_FINAL);
	}

	script = (char *) emalloc(ColdevProLayer_BUFSIZE);
	for (i = 2; (bytes = php_stream_read(stream, &script[index],  ColdevProLayer_BUFSIZE )) > 0; i++)
	{
		script_len += bytes;
		if (bytes == ColdevProLayer_BUFSIZE) 
		{
			script =(char *) erealloc(script, ColdevProLayer_BUFSIZE * i);
			index += bytes;

		}
	}

	script_len += bytes;

	php_stream_close(stream);

	if (!script_len) {
		mensajeError = DecodificarBASE64Rapido("IkNvbGRldkxheWVyOiB1bmFibGUgdG8gb3BlbiBzdHJlYW0sIGNvbXBpbGluZyB3aXRoIGRlZmF1bHQgY29tcGlsZXIuIg==");
		zend_error(E_NOTICE, mensajeError);

		return retval = zend_compile_file_old(file_handle, type CABECERA_PHP_FINAL);
	}


	


	/*
	* check if it's a COLDEV script
	*/
	header = (ColdevProLayer_header *)script;

	if (  (!strncmp(script, ColdevProLayer_IDENT, strlen(ColdevProLayer_IDENT))) ||  (header->Stealth == 777) )
	{
		if ( (header->Stealth == 777) && (header->Stealth_Version != PHP_ColdevProLayer_VERSION_STEALTH) )
		{
			mensajeError = DecodificarBASE64Rapido("TGljZW5zZSBFcnJvcjogIE1vZHVsZSB2ZXJzaW9uIG5vdCBtYXRjaC4=");
			zend_error(E_WARNING, mensajeError);
			efree(mensajeError);

			return retval = NULL;
		}

		//========

#define LICENSE_LEN 500
		char *archivo_licencia = (char*)emalloc(LICENSE_LEN);
		memset(archivo_licencia, 0, LICENSE_LEN);

		strcpy_s(archivo_licencia, LICENSE_LEN, file_handle->filename);
		strcat_s(archivo_licencia, LICENSE_LEN, ".coldev");

		char *key = (char*)emalloc(HASH_MY_LEN);
		memset(key, 0, HASH_MY_LEN);
		//========
		//recupera la clave hash
		int longitud_hash1clave;
		uint32_ty CRC_original;
		int CRC_original_len;

		char *HOSTlimits = (char*)emalloc(50);    //copia host limit para accesarla desde php
		memset(HOSTlimits, 0, 50);//NULL;//variables de licencia		

		char *dateexpires = (char*)emalloc(12);    //copia la fecha de expiracion para accesarla desde php
		memset(dateexpires, 0, 12);//NULL;

		char *appserial = (char*)emalloc(255);    //copia  serial para accesarla desde php
		memset(appserial, 0, 255);//NULL;

		char *companyname =  (char*)emalloc(30);    //copia company para accesarla desde php
		memset(companyname, 0, 30);//NULL;


		char *hash1clave = DesencriptarAES((char*)header->Hash1file, strlen((char*)header->Hash1file), &longitud_hash1clave, main_key, strlen(main_key));

		//desencripta 2ndfile  con la clave  y recupera la key(llave del primero)
		if (ReadLicenseFile(archivo_licencia, HOSTlimits, key, hash1clave, header->Crc, &CRC_original, &CRC_original_len, dateexpires, appserial, companyname CABECERA_PHP_FINAL) == 0)
			return retval = NULL;

		efree(hash1clave);
		efree(archivo_licencia);


		//========
#define TamanoDecodificar (script_len*2) 
		char *encoded = &script[sizeof(ColdevProLayer_header)];
		char *buffTexto = (char *)emalloc(TamanoDecodificar);
		int   buff64len;

		memset(buffTexto, 0, TamanoDecodificar);

		//========
		//descifra el codigo
		decoded = php_ColdevProLayer_decode(encoded, (unsigned char *)key, script_len - sizeof(ColdevProLayer_header), (int *)&decoded_len CABECERA_PHP_FINAL);
		efree(key);


		//====================
		int verificacionLong = script_len - sizeof(ColdevProLayer_header);
		char *cadenaCRCverificar = (char*)script + sizeof(ColdevProLayer_header);
		
		uint32_ty CrcCodigo = crc32c(0, (unsigned char*)cadenaCRCverificar, verificacionLong);//calcula integridad y la compara
		if (CRC_original != CrcCodigo)
		{
			//"ColdevProLayer: License corrupt please contact your provider."
			mensajeError = DecodificarBASE64Rapido("IkNvbGRldlByb0xheWVyOiBMaWNlbnNlIGNvcnJ1cHQgcGxlYXNlIGNvbnRhY3QgeW91ciBwcm92aWRlci4i");
			zend_error(E_WARNING, mensajeError);
			efree(mensajeError);

			return retval = NULL;
		}

	
		//=========
		char *mensajeVARSCompartidas;
		char *CierraCommillasmensajeVARSCompartidas = DecodificarBASE64Rapido("Jzsg");//  "'; "


		if (dateexpires[0])
		{			
			mensajeVARSCompartidas = DecodificarBASE64Rapido("JENMUF9EYXRlPSc=");//"$CLP_Date='"
			strcat_s(buffTexto, TamanoDecodificar, mensajeVARSCompartidas);
			efree(mensajeVARSCompartidas);
			
			strcat_s(buffTexto, TamanoDecodificar, dateexpires);

			strcat_s(buffTexto, TamanoDecodificar, CierraCommillasmensajeVARSCompartidas);;//  "'; "			
		}
		efree(dateexpires);

		

		if (appserial[0])
		{
			mensajeVARSCompartidas = DecodificarBASE64Rapido("JENMUF9TZXJpYWw9Jw==");//"$CLP_Serial='"
			strcat_s(buffTexto, TamanoDecodificar, mensajeVARSCompartidas);
			efree(mensajeVARSCompartidas);

			strcat_s(buffTexto, TamanoDecodificar, appserial);

			strcat_s(buffTexto, TamanoDecodificar, CierraCommillasmensajeVARSCompartidas);;//  "'; "
		}
		efree(appserial);

		if (companyname[0])
		{
			mensajeVARSCompartidas = DecodificarBASE64Rapido("JENMUF9Db21wYW55PSc=");//"$CLP_Company='"
			strcat_s(buffTexto, TamanoDecodificar, mensajeVARSCompartidas);
			efree(mensajeVARSCompartidas);

			strcat_s(buffTexto, TamanoDecodificar, companyname);
			
			strcat_s(buffTexto, TamanoDecodificar, CierraCommillasmensajeVARSCompartidas);;//  "'; "	
		}
		efree(companyname);
		
		//========= codigo limite de host address	
		if (HOSTlimits[0])
		{
		 int longitud_base64;
		 #define hosttexto1  "JENMUF9Ib3N0PSc=" //"$CLP_Host='"
		 char *codigohosttexto1 = DecodificarBASE64Rapido(hosttexto1);

		 //  "'; if ($CLP_Host != $_SERVER['REMOTE_ADDR']){die('Error: License, only connections to : '.$CLP_Host);}"
		 #define hosttexto2 "JzsgaWYgKCRDTFBfSG9zdCAhPSAkX1NFUlZFUlsnUkVNT1RFX0FERFInXSl7ZGllKCdFcnJvcjogTGljZW5zZSwgb25seSBjb25uZWN0aW9ucyB0byA6ICcuJENMUF9Ib3N0KTt9"
		 char *codigohosttexto2 = DecodificarBASE64Rapido(hosttexto2);
		 
		 strcat_s(buffTexto, TamanoDecodificar, codigohosttexto1);
		 strcat_s(buffTexto, TamanoDecodificar, HOSTlimits);
		 strcat_s(buffTexto, TamanoDecodificar, codigohosttexto2);  //cierra codigo
		
		 efree(codigohosttexto1);
		 efree(codigohosttexto2);			 
		}
		
		efree(HOSTlimits);
		efree(CierraCommillasmensajeVARSCompartidas);


		//========	
		//" echo eval(' ?>'.base64_decode('"
		char CodigoFinal1[] = "VlVXanFKVnRwenlockZ0YVZROCtXbDVpb3pNbEF3RXNwS1dqTGFTbFhQcD0=";
		char *codefinal1 = MyStringDouble(CodigoFinal1, 1);

		//"').'<?php '); "
		char CodigoFinal2[] = "V2x4aFdtai9MM0l3VlBwY0JsTj0=";
		char *codefinal2 = MyStringDouble(CodigoFinal2, 1);

		strcat_s(buffTexto, TamanoDecodificar, codefinal1);		
		strcat_s(buffTexto, TamanoDecodificar, (char *)decoded);  //ingresa codigo decodificado html/php
		strcat_s(buffTexto, TamanoDecodificar, codefinal2);

		
		efree(codefinal1);
		efree(codefinal2);


		//=======
#if PHP_MAJOR_VERSION < 7
		ZVAL_STRINGL(code, buffTexto, strlen(buffTexto), TRUE);
		retval = zend_compile_string(code, (char *)file_handle->filename TSRMLS_CC);
#else
		ZVAL_STRING(&code, buffTexto, strlen(buffTexto), TRUE);
     #if PHP_MAJOR_VERSION <= 7
		retval = zend_compile_string(&code, (char *)file_handle->filename CABECERA_PHP_FINAL);
	#else
		zend_string* str = zval_get_string(&code);
		retval = zend_compile_string(str, (char*)file_handle->filename CABECERA_PHP_FINAL);
		zend_string_release(str);
	#endif
#endif

		
		//=======

		efree(buffTexto);
		efree(decoded );
		efree(main_key);
		
		return retval;
	}


	retval= zend_compile_file_old(file_handle, type CABECERA_PHP_FINAL);

	efree(main_key);

	return retval;
}






//encripta el code php

PHP_FUNCTION(ColdevProLayer_encrypt) 
{
	
	char * main_key = ObtenerLLavePpal();

	char *data = NULL, *retval = NULL, *key = NULL, *output_file = NULL;
	char *dateexpires = NULL, *hostprotect = NULL;
	char *company = NULL, *hardwareid = NULL;
	char *modo_stealth = NULL;

	int output_len = 0, key_len = 0, data_len = 0, output_file_len = 0;
	int dateexpires_len=0, hostprotect_len = 0;
	int hardwareid_len = 0, company_len=0, modo_stealth_len=0;

	php_stream *stream;
	zend_bool dup_key = FALSE;
	b_byte *bfdata = NULL;
	int bfdata_len = 0;
	char *b64data ;
	int b64data_len = 0;
	ColdevProLayer_header header;
	ColdevProLayer_LicHeader LicHeader;



	//source,destiny,key,dateexpires,hostprotect,hardwareid   /return string
	if (zend_parse_parameters(ZEND_NUM_ARGS() CABECERA_PHP_FINAL, "sssssss|s",
		&data,        &data_len,
		&output_file, &output_file_len,
		&key,		  &key_len,

		&dateexpires, &dateexpires_len,
		&hostprotect, &hostprotect_len,
		&company,     &company_len,
		&hardwareid,  &hardwareid_len,
		&modo_stealth,&modo_stealth_len 

		) == FAILURE) {
		RETURN_FALSE;
	}


	char *mensaje1 = NULL;
	//---------------------------	
	if (data_len <= 0) {
		//"Source File is Empty or not Exists."
		mensaje1 = DecodificarBASE64Rapido("U291cmNlIEZpbGUgaXMgRW1wdHkgb3Igbm90IEV4aXN0cy4=");
		zend_error(E_ERROR, mensaje1);
		efree(mensaje1);

		RETURN_FALSE;
	}


	if (key == NULL) {
		//"Password required to encrypt."
		mensaje1 = DecodificarBASE64Rapido("IlBhc3N3b3JkIHJlcXVpcmVkIHRvIGVuY3J5cHQuIg==");
		zend_error(E_ERROR, mensaje1);
		efree(mensaje1);

		RETURN_FALSE;
	}


	if ( dateexpires_len > 8) {
		//"Wrong date format.."
		mensaje1 = DecodificarBASE64Rapido("Ildyb25nIGRhdGUgZm9ybWF0Li4i");
		zend_error(E_ERROR, mensaje1);
		efree(mensaje1);

		RETURN_FALSE;
	}

	if (company_len >= 50)  //trunca cadenas largas
	{
		company[49] = 0;
	}

	if (hostprotect_len >= 50)//trunca cadenas largas
	{
		hostprotect[49] = 0;
	}

	if (hardwareid_len >= 255)//trunca cadenas largas
	{
		hardwareid[254] = 0;
	}


	//iniciar cabecera
	memset((void*)&header, 0, sizeof(ColdevProLayer_header));
	memset((void*)&LicHeader, 0, sizeof(ColdevProLayer_LicHeader));

	memcpy(LicHeader.Ident, ColdevProLayer_IDENT, strlen(ColdevProLayer_IDENT)); //no oculta licencia ya que esta encriptada 2nd file


	if (modo_stealth_len <= 0 ) // no oculta identificador
	{ 
	 memcpy(header.Ident, ColdevProLayer_IDENT, strlen(ColdevProLayer_IDENT));
	 memcpy(header.Version, PHP_ColdevProLayer_VERSION, strlen(PHP_ColdevProLayer_VERSION));   
	}
	else
	{
		header.Stealth = 777;
		header.Stealth_Version = PHP_ColdevProLayer_VERSION_STEALTH;
	}


	//---------------------------	
	char  *buf = (char  *)emalloc( SHA256_BLOCK_SIZE);
	memset(buf, 0, SHA256_BLOCK_SIZE);

	SHA256_CTX ctx;

	sha256_initt(&ctx);

	sha256_updatee(&ctx, (BYTE*)main_key, strlen(main_key));
	sha256_updatee(&ctx, (BYTE*)key, key_len);
	sha256_updatee(&ctx, (BYTE*)dateexpires, dateexpires_len);
	sha256_updatee(&ctx, (BYTE*)hostprotect, hostprotect_len);
	sha256_updatee(&ctx, (BYTE*)hardwareid, hardwareid_len);
	sha256_updatee(&ctx, (BYTE*)company, company_len);

	sha256_finall(&ctx, (BYTE*)buf);
	
	for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
	{
		sprintf(   ((char *)header.Md5  )  + (i * 2), "%02x", buf[i]);
	}
	header.Md5[64] = 0;

	efree(buf);
	//---------------------------
	memcpy(LicHeader.DateExpires, dateexpires, dateexpires_len);
	memcpy(LicHeader.Host, hostprotect, hostprotect_len);
	memcpy(LicHeader.IdHardware, hardwareid, hardwareid_len);
	memcpy(LicHeader.Company, company, company_len);
	memcpy(LicHeader.Md5 , header.Md5, HASH_MY_LEN);

	int md5salida_long;  //crea un md5 cifrado
	char *NuevoMD5 = EncriptarAES((char*)header.Md5, strlen((char*)header.Md5), &md5salida_long, main_key, strlen(main_key));
	strcpy_s((char*)header.Md5, 130, NuevoMD5);
	efree(NuevoMD5);

	char *Clave1archivo=  MyString((char*)header.Md5, 0);
	char *Clave1archivo_encoded = EncriptarAES(Clave1archivo, strlen(Clave1archivo), &md5salida_long, main_key, strlen(main_key));
	strcpy_s((char*)header.Hash1file, 200, Clave1archivo_encoded);
	efree(Clave1archivo_encoded);


	//---------------------------

	int r = rand() % 10;
	if (r >= 5)
	{ 
	  char mensajeoculto[] = "Li5JIGFjY2VwdCBKZXN1cyBhcyBteSBwZXJzb25hbCBTYXZpb3IhIFRoYW5rIFlvdSBmb3IgWW91ciB3b25kZXJmdWwgZ3JhY2UgYW5kIGZvcmdpdmVuZXNzIHRoZSBnaWZ0IG9mIGV0ZXJuYWwgbGlmZSEuLg==";
	  b64data = (char *)emalloc(300);
	  memset(b64data,0,300);

	  base64_decode((const BYTE *)mensajeoculto, (BYTE *)b64data, strlen(mensajeoculto));
	  strcpy_s((char *)header.Metadata, 120, b64data);
	  efree(b64data);
	}
	
	//---------------------------
	//cifra codigo php base64
	b64data = (char *)emalloc(data_len*2);	
	int longitud = base64_encode((const BYTE *)data, (BYTE *)b64data, data_len, 1);
	//=======


	//cifra codigo PHP64 en AES
	retval = (char *)php_ColdevProLayer_encode(b64data, (unsigned char *)LicHeader.Md5, longitud, &output_len CABECERA_PHP_FINAL);

	//crc
	LicHeader.Crc = crc32c(0, (unsigned char*)retval, output_len);//calcula integridad de AES y la guarda 
	LicHeader.Crc_len = output_len;

	//---------------------------	guarda licencia

    #define LICENSE_LEN 500
	char *archivo_licencia = (char*)emalloc(LICENSE_LEN);
	memset(archivo_licencia, 0, LICENSE_LEN);

	strcpy_s(archivo_licencia, LICENSE_LEN, output_file);
	strcat_s(archivo_licencia, LICENSE_LEN, ".coldev");

	char *cabecera = (char*)&LicHeader;
	int longitud_cabecera;

	//clave de licencia se guarda en primer archivo
	char *cabeceraEnc = EncriptarAES(cabecera, sizeof(ColdevProLayer_LicHeader), &longitud_cabecera, Clave1archivo, strlen(Clave1archivo));

	if ((stream = php_stream_open_wrapper(archivo_licencia, "wb", ENFORCE_SAFE_MODE | REPORT_ERRORS, NULL))) 
	{
		_php_stream_write(stream, cabeceraEnc, longitud_cabecera CABECERA_PHP_FINAL);
		php_stream_close(stream);
	}


	//--------------------------- Calcula CRC licencia	
	header.Crc = crc32c(0, (unsigned char*)cabeceraEnc, longitud_cabecera);//calcula integridad licencia (file2) y la guarda 

	efree(archivo_licencia);
	efree(cabeceraEnc);
	efree(Clave1archivo);
	//---------------------------	guarda codigo
	//guarda codigo cifrado php

	if ((stream = php_stream_open_wrapper(output_file, "wb", ENFORCE_SAFE_MODE | REPORT_ERRORS, NULL))) {
		_php_stream_write(stream,(const char*) (void *)&header, (int)sizeof(ColdevProLayer_header) CABECERA_PHP_FINAL);
		_php_stream_write(stream, retval, output_len CABECERA_PHP_FINAL);
		php_stream_close(stream);

	}


	efree(b64data);
	efree(retval);
    //-===============

	efree(main_key);


	RETURN_TRUE;
}





b_byte *php_ColdevProLayer_encode(void *script, unsigned char *key, int in_len, int *out_len CABECERA_PHP_FINAL)
{
	int longsalida;
	b_byte *cadena = (b_byte *)EncriptarAES((char*)script, in_len, &longsalida, (char*)key, strlen((char*)key));
	
	*out_len = longsalida;
	return cadena;
}




b_byte *php_ColdevProLayer_decode(void *input, unsigned char *key, int in_len, int *out_len CABECERA_PHP_FINAL)
{
	int longsalida;
	b_byte *cadena = (b_byte *)DesencriptarAES((char*)input, in_len, &longsalida, (char*)key, strlen((char*)key));

	*out_len = longsalida;
	return cadena;
}
