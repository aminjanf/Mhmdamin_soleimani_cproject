#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mkjson.h"
#include <stdarg.h>
#include <string.h>

// enc

unsigned char*encrypt_block(unsigned char k[4],unsigned char*p,unsigned char**state) {
    unsigned char**k_ = key_schedule(k,2);
    unsigned char A[4];
    for(int i=0; i<4; i++) A[i] = p[i] ^ k_[0][i];              // KeyAddition K_0
    unsigned char B[4];
    for(int i=0; i<4; i++) B[i] = nibbleSub(A[i]);              // NibbleSub
    unsigned char c[][2] = {{B[0],B[2]},{B[1],B[3]}};
    unsigned char**c_ = shiftRow(2,2,matrixToPointer(2,2,c));   // ShiftRow
    unsigned char C[] = {c_[0][0],c_[1][0],c_[0][1],c_[1][1]};
    unsigned char**d = matrix_multiplication(state,c_,2,2,2,2); // MixColumn
    unsigned char D[] = {d[0][0],d[1][0],d[0][1],d[1][1]};
    unsigned char E[4];
    for(int i=0; i<4; i++) E[i] = D[i] ^ k_[1][i];              // KeyAddition K_1
    unsigned char F[4];
    for(int i=0; i<4; i++) F[i] = nibbleSub(E[i]);              // NibbleSub
    unsigned char g[][2] = {{F[0],F[2]},{F[1],F[3]}};
    unsigned char**g_ = shiftRow(2,2,matrixToPointer(2,2,g));   // ShiftRow
    unsigned char G[] = {g_[0][0],g_[1][0],g_[0][1],g_[1][1]};
    unsigned char H[4];
    for(int i=0; i<4; i++) H[i] = G[i] ^ k_[2][i];              // KeyAddition K_2
    free(c_);
    free(d);
    free(g_);   // free memory
    free(k_);

    unsigned char*result = malloc(4*sizeof(char));
    memcpy(result,H,4); // save result
    return result;
}

unsigned char*encrypt(unsigned char k[4],unsigned char*p,unsigned char**state,int length) {
    unsigned char*m_encrypt = malloc(length*sizeof(char));
    for(int i=0; i<length/4; i++)
        memcpy(m_encrypt+i*4,encrypt_block(k,p+i*4,state),4);
    return m_encrypt;
}

int main(int argc, char *argv[]) {
    unsigned char m1[][2] = {{0b0011,0b0010},
                             {0b0010,0b0011}};

    unsigned char**state = matrixToPointer(2,2,m1);

    unsigned char k[] = {0b1100,0b0011,0b1111,0b0000};  // set secret key

    FILE*source  = fopen(argv[1],"rb");
    FILE*destiny = fopen(argv[2],"wb");

    int tam = 2;
    unsigned char*p,*enc,buffer[2];

    while(tam == 2) {
        memset(buffer,0,2);
        tam = fread(buffer,1,2,source); // get 2 bytes from source file
        p   = split(buffer);            // 2 bytes to 4 nibbles
        enc = encrypt_block(k,p,state); // encrypt
        enc = join(enc);                // 4 nibbles to 2 bytes
        fwrite(enc,1,2,destiny);        // save 2 encrypted bytes inside the encrypted file
        free(p);
        free(enc);
    }

    free(state);
    fclose(source);
    fclose(destiny);
    return 0;
}

// fs io

#define FSIO_READ_BUFFER_SIZE    1024

const mode_t FSIO_MODE_ALL = S_IRWXU | S_IRWXG | S_IRWXO;

static bool _fsio_load_stat(char *, struct stat *);
static bool _fsio_write_file(char *, char *, char *, bool, size_t);
static char *_fsio_read_file_with_options(char *, char *, struct FsIOReadFileOptions);
static bool _fsio_remove_callback(struct FsIORecursiveCallbackInfo);
static bool _fsio_chmod_recursive_callback(struct FsIORecursiveCallbackInfo);
static bool _fsio_recursive_operation(char *, bool (*callback)(struct FsIORecursiveCallbackInfo), void *, struct StringBuffer *);


long fsio_file_size(char *file)
{
  if (!fsio_file_exists(file))
  {
    return(-1);
  }

  FILE *fp = fopen(file, "rb");
  if (fp == NULL)
  {
    return(-1);
  }

  long current_position = ftell(fp);

  fseek(fp, 0L, SEEK_END);
  long size = ftell(fp);

  // set back to original position
  fseek(fp, current_position, SEEK_SET);

  fclose(fp);

  return(size);
}


bool fsio_write_text_file(char *file, char *text)
{
  return(_fsio_write_file(file, text, "w", true, 0));
}


bool fsio_append_text_file(char *file, char *text)
{
  return(_fsio_write_file(file, text, "a", true, 0));
}


char *fsio_read_text_file(char *file)
{
  struct FsIOReadFileOptions options;

  options.max_read_limit = 0;
  options.tail           = false;

  return(fsio_read_text_file_with_options(file, options));
}


char *fsio_read_text_file_with_options(char *file, struct FsIOReadFileOptions options)
{
  return(_fsio_read_file_with_options(file, "r", options));
}


bool fsio_write_binary_file(char *file, char *content, size_t length)
{
  return(_fsio_write_file(file, content, "wb", false, length));
}


bool fsio_append_binary_file(char *file, char *content, size_t length)
{
  return(_fsio_write_file(file, content, "ab", false, length));
}


char *fsio_read_binary_file(char *file)
{
  struct FsIOReadFileOptions options;

  options.max_read_limit = 0;
  options.tail           = false;

  return(fsio_read_binary_file_with_options(file, options));
}


char *fsio_read_binary_file_with_options(char *file, struct FsIOReadFileOptions options)
{
  return(_fsio_read_file_with_options(file, "rb", options));
}


bool fsio_create_empty_file(char *file)
{
  return(fsio_write_binary_file(file, "", 0));
}


bool fsio_copy_file(char *source, char *target)
{
  struct FsIOCopyFileOptions options;

  options.write_retries          = 0;
  options.retry_interval_seconds = 0;

  return(fsio_copy_file_with_options(source, target, options));
}


bool fsio_copy_file_with_options(char *source, char *target, struct FsIOCopyFileOptions options)
{
  if (source == NULL || target == NULL)
  {
    return(false);
  }

  long file_size = fsio_file_size(source);
  if (!file_size)
  {
    return(fsio_create_empty_file(target));
  }

  FILE *source_fp = fopen(source, "r");
  if (source_fp == NULL)
  {
    return(false);
  }

  FILE *target_fp = fopen(target, "w");
  if (target_fp == NULL)
  {
    fclose(source_fp);
    return(false);
  }

  bool delete_file                      = false;
  long left_to_read                     = file_size;
  char io_buffer[FSIO_READ_BUFFER_SIZE] = { 0 };
  do
  {
    if (feof(source_fp))
    {
      break;
    }

    long to_read = FSIO_READ_BUFFER_SIZE;
    if (to_read > left_to_read)
    {
      to_read = left_to_read;
    }

    size_t read = fread(io_buffer, 1, (size_t)to_read, source_fp);
    if (!read)
    {
      delete_file = true;
      break;
    }
    else
    {
      left_to_read = left_to_read - (long)read;
    }

    size_t written = fwrite(io_buffer, 1, read, target_fp);
    if (written < read)
    {
      delete_file = true;
      break;
    }
  } while (left_to_read > 0);

  fclose(source_fp);
  fclose(target_fp);

  if (delete_file)
  {
    remove(target);

    if (options.write_retries > 0)
    {
      if (options.retry_interval_seconds)
      {
        sleep(options.retry_interval_seconds);
      }
      options.write_retries = options.write_retries - 1;

      return(fsio_copy_file_with_options(source, target, options));
    }

    return(false);
  }

  return(true);
}   /* fsio_copy_file_with_options */


bool fsio_move_file(char *source, char *target)
{
  struct FsIOMoveFileOptions options;

  options.force_copy             = false;
  options.write_retries          = 0;
  options.retry_interval_seconds = 0;

  enum FsIOError error = fsio_move_file_with_options(source, target, options);

  return(error == FSIO_ERROR_NONE);
}


enum FsIOError fsio_move_file_with_options(char *source, char *target, struct FsIOMoveFileOptions options)
{
  if (source == NULL || target == NULL)
  {
    return(FSIO_ERROR_INVALID_INPUT);
  }
  if (!fsio_file_exists(source))
  {
    return(FSIO_ERROR_PATH_NOT_FOUND);
  }

  if (!options.force_copy)
  {
    if (!rename(source, target))
    {
      return(FSIO_ERROR_NONE);
    }

    if (errno != EXDEV)
    {
      return(FSIO_ERROR_SEE_ERRNO);
    }
  }

  struct FsIOCopyFileOptions copy_options;
  copy_options.write_retries          = options.write_retries;
  copy_options.retry_interval_seconds = options.retry_interval_seconds;
  bool copy_done = fsio_copy_file_with_options(source, target, copy_options);
  if (copy_done)
  {
    fsio_remove(source);
  }

  if (!copy_done)
  {
    return(FSIO_ERROR_COPY_FAILED);
  }

  return(FSIO_ERROR_NONE);
} /* fsio_move_file_with_options */


char *fsio_file_extension(char *path)
{
  if (path == NULL)
  {
    return(NULL);
  }

  size_t length = strlen(path);
  if (!length)
  {
    return(NULL);
  }

  size_t extension_index = 0;
  bool   found           = false;
  for (size_t index = length - 1; ; index--)
  {
    char character = path[index];
    if (character == '/' || character == '\\')
    {
      return(NULL);
    }

    if (character == '.')
    {
      found           = true;
      extension_index = index;
      break;
    }

    if (!index)
    {
      break;
    }
  }

  if (!found)
  {
    return(NULL);
  }

  size_t extension_length = length - extension_index;
  if (extension_length <= 1)
  {
    return(NULL);
  }

  char *extension = malloc(sizeof(char) * (extension_length + 1));
  for (size_t index = 0; index < extension_length; index++)
  {
    extension[index] = path[extension_index + index];
  }
  extension[extension_length] = '\0';

  return(extension);
} /* fsio_get_file_extension */


char *fsio_join_paths(char *path1, char *path2)
{
  if (path1 == NULL)
  {
    if (path2 == NULL)
    {
      return(NULL);
    }

    return(strdup(path2));
  }
  if (path2 == NULL)
  {
    return(strdup(path1));
  }

  size_t len1 = strlen(path1);
  if (!len1)
  {
    return(strdup(path2));
  }
  size_t len2 = strlen(path2);
  if (!len2)
  {
    return(strdup(path1));
  }

  bool   path1_ends_with_separator   = path1[len1 - 1] == '/' || path1[len1 - 1] == '\\';
  bool   path2_starts_with_separator = path2[0] == '/' || path2[0] == '\\';
  bool   need_to_add_separator       = !path1_ends_with_separator && !path2_starts_with_separator;
  bool   need_to_remove_separator    = path1_ends_with_separator && path2_starts_with_separator;

  size_t concat_len = len1 + len2;
  if (need_to_add_separator)
  {
    concat_len = concat_len + 1;
  }
  else if (need_to_remove_separator)
  {
    concat_len = concat_len - 1;
  }

  char *concat_path = malloc(sizeof(char) * (concat_len + 1));

  for (size_t index = 0; index < len1; index++)
  {
    concat_path[index] = path1[index];
  }
  size_t offset = len1;
  if (need_to_add_separator)
  {
    concat_path[len1] = '/';
    offset            = offset + 1;
  }
  else if (need_to_remove_separator)
  {
    offset = offset - 1;
  }
  for (size_t index = 0; index < len2; index++)
  {
    concat_path[offset + index] = path2[index];
  }

  concat_path[concat_len] = 0;

  return(concat_path);
} /* fsio_join_paths */


bool fsio_path_exists(char *path)
{
  struct stat info;

  return(_fsio_load_stat(path, &info));
}


bool fsio_file_exists(char *path)
{
  struct stat info;

  if (!_fsio_load_stat(path, &info))
  {
    return(false);
  }

  return(S_ISREG(info.st_mode));
}


bool fsio_dir_exists(char *path)
{
  struct stat info;

  if (!_fsio_load_stat(path, &info))
  {
    return(false);
  }

  return(S_ISDIR(info.st_mode));
}


bool fsio_mkdir(char *directory, mode_t mode)
{
  if (directory == NULL)
  {
    return(false);
  }

  if (fsio_dir_exists(directory))
  {
    return(true);
  }

  int result = mkdir(directory, mode);

  if (result == 0 || errno == EEXIST)
  {
    return(true);
  }

  return(false);
}


bool fsio_mkdirs(char *directory, mode_t mode)
{
  if (directory == NULL)
  {
    return(false);
  }

  if (fsio_mkdir(directory, mode))
  {
    return(true);
  }

  char *directory_mutable = strdup(directory);

  for (char *path = directory_mutable; *path != 0; path++)
  {
    if (*path == '/')
    {
      *path = '\0';

      if (strlen(directory_mutable))
      {
        if (!fsio_mkdir(directory_mutable, mode))
        {
          free(directory_mutable);
          return(false);
        }
      }

      *path = '/';
    }
  }

  free(directory_mutable);

  return(fsio_mkdir(directory, mode));
}


bool fsio_mkdirs_parent(char *path, mode_t mode)
{
  if (path == NULL)
  {
    return(false);
  }

  char *path_clone = strdup(path);
  char *directory  = dirname(path_clone);

  if (directory == NULL)
  {
    free(path_clone);
    return(false);
  }

  bool done = fsio_mkdirs(directory, mode);
  free(path_clone);

  return(done);
}


bool fsio_remove(char *path)
{
  if (path == NULL)
  {
    return(true);
  }

  return(fsio_recursive_operation(path, _fsio_remove_callback, NULL));
}


bool fsio_chmod_recursive(char *path, mode_t mode)
{
  mode_t mode_ptr[1];

  mode_ptr[0] = mode;

  return(fsio_recursive_operation(path, _fsio_chmod_recursive_callback, mode_ptr));
}


bool fsio_recursive_operation(char *path, bool (*callback)(struct FsIORecursiveCallbackInfo), void *context)
{
  if (path == NULL)
  {
    return(false);
  }

  struct StringBuffer *buffer = stringbuffer_new();
  bool                done    = _fsio_recursive_operation(path, callback, context, buffer);
  stringbuffer_release(buffer);

  return(done);
}


static bool _fsio_load_stat(char *path, struct stat *info)
{
  if (path == NULL)
  {
    return(false);
  }

  if (stat(path, info) != 0)
  {
    return(false);
  }

  return(true);
}


static bool _fsio_write_file(char *file, char *content, char *mode, bool is_text, size_t length)
{
  if (file == NULL || content == NULL)
  {
    return(false);
  }

  if (is_text)
  {
    length = strlen(content);
  }

  bool directory_created = fsio_mkdirs_parent(file, FSIO_MODE_ALL);
  if (!directory_created)
  {
    return(false);
  }

  FILE *fp = fopen(file, mode);
  if (fp == NULL)
  {
    return(false);
  }

  size_t written = fwrite(content, 1, length, fp);
  if (written < length)
  {
    fclose(fp);

    // prevent partially written file to be
    remove(file);

    return(false);
  }

  fflush(fp);
  fclose(fp);

  return(true);
}


static char *_fsio_read_file_with_options(char *file, char *mode, struct FsIOReadFileOptions options)
{
  long file_size = fsio_file_size(file);

  if (file_size < 0)
  {
    return(NULL);
  }
  if (!file_size)
  {
    return(strdup(""));
  }

  FILE *fp = fopen(file, mode);
  if (fp == NULL)
  {
    return(NULL);
  }

  long left_to_read = file_size;
  if (options.max_read_limit > 0 && left_to_read > options.max_read_limit)
  {
    left_to_read = options.max_read_limit;

    if (options.tail)
    {
      fseek(fp, (-1) * left_to_read, SEEK_END);
    }
  }

  struct StringBuffer *buffer                          = stringbuffer_new();
  char                io_buffer[FSIO_READ_BUFFER_SIZE] = { 0 };
  do
  {
    if (feof(fp))
    {
      break;
    }

    long to_read = FSIO_READ_BUFFER_SIZE;
    if (to_read > left_to_read)
    {
      to_read = left_to_read;
    }

    size_t read = fread(io_buffer, 1, (size_t)to_read, fp);
    if (!read)
    {
      break;
    }
    else
    {
      left_to_read = left_to_read - (long)read;
    }

    stringbuffer_append_binary(buffer, io_buffer, 0, read);
  } while (left_to_read > 0);

  fclose(fp);

  char *text = stringbuffer_to_string(buffer);

  stringbuffer_release(buffer);

  return(text);
} /* _fsio_read_file_with_options */


static bool _fsio_remove_callback(struct FsIORecursiveCallbackInfo info)
{
  return(remove(info.path) == 0);
}


static bool _fsio_chmod_recursive_callback(struct FsIORecursiveCallbackInfo info)
{
  mode_t *mode = (mode_t *)info.context;

  return(chmod(info.path, mode[0]) == 0);
}


static bool _fsio_recursive_operation(char *path, bool (*callback)(struct FsIORecursiveCallbackInfo), void *context, struct StringBuffer *buffer)
{
  struct FsIORecursiveCallbackInfo info;

  info.context = context;
  info.path    = path;
  info.is_file = true;

  if (fsio_file_exists(path))
  {
    return(callback(info));
  }

  if (fsio_dir_exists(path))
  {
    DIR *directory = opendir(path);
    if (directory == NULL)
    {
      return(false);
    }

    struct dirent *entry;
    while ((entry = readdir(directory)))
    {
      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      {
        // skip special directories
        continue;
      }

      stringbuffer_append_string(buffer, path);
      stringbuffer_append(buffer, '/');
      stringbuffer_append_string(buffer, entry->d_name);

      char *entry_path = stringbuffer_to_string(buffer);
      stringbuffer_clear(buffer);

      bool done = false;
      if (fsio_dir_exists(entry_path))
      {
        done = _fsio_recursive_operation(entry_path, callback, context, buffer);
      }
      else
      {
        info.path    = entry_path;
        info.is_file = true;
        done         = callback(info);
      }
      free(entry_path);

      if (!done)
      {
        closedir(directory);
        return(false);
      }
    }

    closedir(directory);

    info.path    = path;
    info.is_file = false;
    return(callback(info));
  }

  return(false);
}   /* _fsio_recursive_operation */

// Works like asprintf, but it's always there
// I don't want the name to collide with anything
static int allsprintf( char **strp, const char *fmt, ... )
{
	int len;
	va_list ap;
	va_start( ap, fmt );

	#ifdef _GNU_SOURCE
		// Just hand everything to vasprintf, if it's available
		len = vasprintf( strp, fmt, ap );
	#else
		// Or do it the manual way
		char *buf;
		len = vsnprintf( NULL, 0, fmt, ap );
		if ( len >= 0 )
		{
			buf = malloc( ++len );
			if ( buf != NULL )
			{
				// Hopefully, that's the right way to do it
				va_end( ap );
				va_start( ap, fmt );

				// Write and return the data
				len = vsnprintf( buf, len, fmt, ap );
				if ( len >= 0 )
				{
					*strp = buf;
				}
				else
				{
					free( buf );
				}
			}
		}
	#endif

	va_end( ap );
	return len;
}

// Return JSON string built from va_arg arguments
// If no longer needed, should be passed to free() by user
char *mkjson( enum mkjson_container_type otype, int count, ... )
{
	int i, len, goodchunks = 0, failure = 0;
	char *json, *prefix, **chunks, ign;

	// Value - type and data
	enum mkjson_value_type vtype;
	const char *key;
	long long int intval;
	long double dblval;
	const char *strval;

	// Since v0.9 count cannot be a negative value and datatype is indicated by a separate argument
	// Since I'm not sure whether it's right to put assertions in libraries, the next line is commented out
	// assert( count >= 0 && "After v0.9 negative count is prohibited; please use otype argument instead" );
	if ( count < 0 || ( otype != MKJSON_OBJ && otype != MKJSON_ARR ) ) return NULL;

	// Allocate chunk pointer array - on standard platforms each one should be NULL
	chunks = calloc( count, sizeof( char* ) );
	if ( chunks == NULL ) return NULL;

	// This should rather be at the point of no return
	va_list ap;
	va_start( ap, count );

	// Create chunks
	for ( i = 0; i < count && !failure; i++ )
	{
		// Get value type
		vtype = va_arg( ap, enum mkjson_value_type );

		// Get key
		if ( otype == MKJSON_OBJ )
		{
			key = va_arg( ap, char* );
			if ( key == NULL )
			{
				failure = 1;
				break;
			}
		}
		else key = "";

		// Generate prefix
		if ( allsprintf( &prefix, "%s%s%s",
			otype == MKJSON_OBJ ? "\"" : "",            // Quote before key
			key,                                        // Key
			otype == MKJSON_OBJ ? "\": " : "" ) == -1 ) // Quote and colon after key
		{
			failure = 1;
			break;
		}

		// Depending on value type
		ign = 0;
		switch ( vtype )
		{
			// Ignore string / JSON data
			case MKJSON_IGN_STRING:
			case MKJSON_IGN_JSON:
				(void) va_arg( ap, const char* );
				ign = 1;
				break;

			// Ignore string / JSON data and pass the pointer to free
			case MKJSON_IGN_STRING_FREE:
			case MKJSON_IGN_JSON_FREE:
				free( va_arg( ap, char* ) );
				ign = 1;
				break;

			// Ignore int / long long int
			case MKJSON_IGN_INT:
			case MKJSON_IGN_LLINT:
				if ( vtype == MKJSON_IGN_INT )
					(void) va_arg( ap, int );
				else
					(void) va_arg( ap, long long int );
				ign = 1;
				break;

			// Ignore double / long double
			case MKJSON_IGN_DOUBLE:
			case MKJSON_IGN_LDOUBLE:
				if ( vtype == MKJSON_IGN_DOUBLE )
					(void) va_arg( ap, double );
				else
					(void) va_arg( ap, long double );
				ign = 1;
				break;

			// Ignore boolean
			case MKJSON_IGN_BOOL:
				(void) va_arg( ap, int );
				ign = 1;
				break;

			// Ignore null value
			case MKJSON_IGN_NULL:
				ign = 1;
				break;

			// A null-terminated string
			case MKJSON_STRING:
			case MKJSON_STRING_FREE:
				strval = va_arg( ap, const char* );

				// If the pointer points to NULL, the string will be replaced with JSON null value
				if ( strval == NULL )
				{
					if ( allsprintf( chunks + i, "%snull", prefix ) == -1 )
						chunks[i] = NULL;
				}
				else
				{
					if ( allsprintf( chunks + i, "%s\"%s\"", prefix, strval ) == -1 )
						chunks[i] = NULL;
				}

				// Optional free
				if ( vtype == MKJSON_STRING_FREE )
					free( (char*) strval );
				break;

			// Embed JSON data
			case MKJSON_JSON:
			case MKJSON_JSON_FREE:
				strval = va_arg( ap, const char* );

				// If the pointer points to NULL, the JSON data is replaced with null value
				if ( allsprintf( chunks + i, "%s%s", prefix, strval == NULL ? "null" : strval ) == -1 )
					chunks[i] = NULL;

				// Optional free
				if ( vtype == MKJSON_JSON_FREE )
					free( (char*) strval );
				break;

			// int / long long int
			case MKJSON_INT:
			case MKJSON_LLINT:
				if ( vtype == MKJSON_INT )
					intval = va_arg( ap, int );
				else
					intval = va_arg( ap, long long int );

				if ( allsprintf( chunks + i, "%s%Ld", prefix, intval ) == -1 ) chunks[i] = NULL;
				break;

			// double / long double
			case MKJSON_DOUBLE:
			case MKJSON_LDOUBLE:
				if ( vtype == MKJSON_DOUBLE )
					dblval = va_arg( ap, double );
				else
					dblval = va_arg( ap, long double );

				if ( allsprintf( chunks + i, "%s%Lf", prefix, dblval ) == -1 ) chunks[i] = NULL;
				break;

			// double / long double
			case MKJSON_SCI_DOUBLE:
			case MKJSON_SCI_LDOUBLE:
				if ( vtype == MKJSON_SCI_DOUBLE )
					dblval = va_arg( ap, double );
				else
					dblval = va_arg( ap, long double );

				if ( allsprintf( chunks + i, "%s%Le", prefix, dblval ) == -1 ) chunks[i] = NULL;
				break;

			// Boolean
			case MKJSON_BOOL:
				intval = va_arg( ap, int );
				if ( allsprintf( chunks + i, "%s%s", prefix, intval ? "true" : "false" ) == -1 ) chunks[i] = NULL;
				break;

			// JSON null
			case MKJSON_NULL:
				if ( allsprintf( chunks + i, "%snull", prefix ) == -1 ) chunks[i] = NULL;
				break;

			// Bad type specifier
			default:
				chunks[i] = NULL;
				break;
		}

		// Free prefix memory
		free( prefix );

		// NULL chunk without ignore flag indicates failure
		if ( !ign && chunks[i] == NULL ) failure = 1;

		// NULL chunk now indicates ignore flag
		if ( ign ) chunks[i] = NULL;
		else goodchunks++;
	}

	// We won't use ap anymore
	va_end( ap );

	// If everything is fine, merge chunks and create full JSON table
	if ( !failure )
	{
		// Get total length (this is without NUL byte)
		len = 0;
		for ( i = 0; i < count; i++ )
			if ( chunks[i] != NULL )
				len += strlen( chunks[i] );

		// Total length = Chunks length + 2 brackets + separators
		if ( goodchunks == 0 ) goodchunks = 1;
		len = len + 2 + ( goodchunks - 1 ) * 2;

		// Allocate memory for the whole thing
		json = calloc( len + 1, sizeof( char ) );
		if ( json != NULL )
		{
			// Merge chunks (and do not overwrite the first bracket)
			for ( i = 0; i < count; i++ )
			{
				// Add separators:
				// - not on the begining
				// - always after valid chunk
				// - between two valid chunks
				// - between valid and ignored chunk if the latter isn't the last one
				if ( i != 0 && chunks[i - 1] != NULL && ( chunks[i] != NULL || ( chunks[i] == NULL && i != count - 1 ) ) )
					strcat( json + 1, ", ");

				if ( chunks[i] != NULL )
					strcat( json + 1, chunks[i] );
			}

			// Add proper brackets
			json[0] = otype == MKJSON_OBJ ? '{' : '[';
			json[len - 1] = otype == MKJSON_OBJ ? '}' : ']';
		}
	}
	else json = NULL;

	// Free chunks
	for ( i = 0; i < count; i++ )
		free( chunks[i] );
	free( chunks );

	return json;
}

struct Menu {
	int ID;
	char * title;
	void * action;
};

void CreateMenu(int * last_strg_id,struct Menu * strg,char * title,void * action){
	struct Menu Menu_t;
	Menu_t.ID = (*last_strg_id)+1;
	Menu_t.title = title;
	Menu_t.action = action;
	struct Menu * strg = (struct Menu)realloc(strg,sizeof(struct Menu));
	*last_strg_id++;
}

void MenuHandler(){
	struct Menu * _Menu;
	int last_menu_identifier = 0;
	_Menu = (struct Menu)malloc(sizeof(struct Menu));
	CreateMenu(&last_menu_identifier,"new message",&add_Message);
}

struct Message
{
	int ID;
	char * msg;
	struct Message * next;
};
void add_Message (struct Message ** first, struct Message ** last, const char * m, int id)
{
	if (*first == NULL)
	{
		(*first) = (struct Message *) malloc (sizeof (struct Message));
		(*first) -> msg = (char *) malloc (strlen(m) + 1);
		strcpy ((*first) -> msg, m);
		(*first) -> ID = id;
		(*first) -> next = NULL;
		(*last) = (*first);
	}
	else
	{
		struct Message * temp = (struct Message *) malloc (sizeof (struct Message));
		temp -> msg = (char *) malloc (strlen(m) + 1);
		strcpy (temp -> msg, m);
		temp -> ID = id;
		temp -> next = NULL;
		(*last) -> next = temp;
		(*last) = temp;
	}

}
void print_Messages (struct Message * temp)
{
	while (temp != NULL)
	{
		printf ("\n   %s", temp -> msg);
		printf ("\n   ID: %d", temp -> ID);
		printf ("\n   -------------------------------------------------");
		temp = temp -> next;
	}
}

struct Message * search_and_edit_ID (struct Message * temp, int id)
{
	while (temp != NULL)
	{
		if (temp -> ID == id)
			return temp;
		temp = temp -> next;
	}
	return NULL;
}

struct User
{
	char * user_name;
	int password;
	struct Message * first, * last;
	struct User * next;
};

static struct User * user = NULL;
static int ID_counter = 0;
struct User * first = NULL, * last = NULL;

void add_User (const char * ptr, int * p)
{
	if (first == NULL)
	{
		first = (struct User *) malloc (sizeof (struct User));
		first -> user_name = (char *) malloc (strlen(ptr) + 1);
		strcpy (first -> user_name, ptr);
		first -> password = *p;
		first -> next = NULL;
		first -> first = first -> last = NULL;
		last = first;
		user = first;
	}
	else
	{
		struct User * temp = (struct User *) malloc (sizeof (struct User));
		temp -> user_name = (char *) malloc (strlen(ptr) + 1);
		strcpy (temp -> user_name, ptr);
		temp -> password = *p;
		temp -> next = NULL;
		temp -> first = temp -> last = NULL;
		last -> next = temp;
		last = temp;
		user = last;
	}
}

int find_User (const char * ptr, int * p)
{
	struct User * temp = first;
	while (temp != NULL)
	{
		if ((strcmp (temp -> user_name, ptr) == 0))
		{
			if ((temp -> password == *p))
			{
				user = temp;
				return 1;
			}
			else
				return 2;
		}
		temp = temp -> next;
	}
	return 3;
}


void Login_signup_menu();
void Main_menu();
void Send_message();
void Edit_message();
void View_all_messages();
void Change_password();

int main ()
{
	while (1)
	{
		Login_signup_menu();
		Main_menu();
	}
	return 0;
}

void Login_signup_menu ()
{
	struct User * temp;
	char user_name[30];
	int password, choice;
	do
	{
		system("clear");
		printf ("\n   -> User name can be a combination of\n      letters and numbers. (with no space)");
		printf ("\n   -> Your password must be integer");
		printf ("\n\n   User name: ");
		scanf ("%s", user_name);
		printf ("\n   Passwrod: ");
		scanf ("%d", &password);
		choice = find_User(user_name, &password);
		if (choice == 2)
		{
			printf("\n   This username has already been taken");
			printf("\n   Choose a different username\n   ");
			system("pause");
		}
		else if (choice == 3)
		{
			add_User (user_name, &password);
			printf("\n   Your registration was successful\n   ");
			system("pause");
		}
	} while (choice == 2);
}
void Display_menu (int * choice)
{
	system("clear");
	printf ("\n\t\t\tWelcome");
	printf ("\n\n   1. Send message");
	printf ("\n   2. Edit message");
	printf ("\n   3. View all messages");
	printf ("\n   4. Change password");
	printf ("\n   5. Exit");
	printf ("\n\n   Enter number of menu: ");
	scanf ("%d", &*choice);
}
void Main_menu ()
{
	int choice;
	do
	{
		Display_menu (&choice);
		switch (choice)
		{
			case 1:  {  Send_message();       break;  }
			case 2:  {  Edit_message();       break;  }
			case 3:  {  View_all_messages();  break;  }
			case 4:  {  Change_password();    break;  }
			case 5:  {						  break;  }
			default: {
				printf ("\n\n   Wrong choice");
				printf ("\n   It has to be between 1 to 5\n   ");
				system("pause");
				system("clear");
				break;
			}
		}
	} while (choice != 5);
}
void print (const char * str)
{
	system("clear");
	printf ("\n\n   1. %s", str);
	printf ("\n   2. Exit");
	printf ("\n\n   Enter number of menu: ");
}
void Send_message()
{
	const int size = 200;
	int choice;
	char str[size];
	do
	{
		print("Send message");
		scanf ("%d", &choice);
		switch (choice)
		{
			case 1:
			{
				system("clear");
				printf ("\n\n   Enter a message: ");
				fseek(stdin,0,SEEK_END);
				scanf ("%[^\n]", str);
				ID_counter++;
				add_Message (&user -> first, &user -> last, str, ID_counter);
				break;
			}
			case 2: break;
			default:
			{
				printf ("\n\n   Wrong choice");
				printf ("\n   It has to be 1 or 2\n   ");
				system("pause");
				break;
			}
		}
	} while (choice != 2);
}
void Edit_message()
{
	const int size = 200;
	char str[size];
	int choice, ID;
	do
	{
		print("Edit message");
		scanf ("%d", &choice);
		switch (choice)
		{
			case 1:
			{
				system("clear");
				printf ("\n\n   Enter ID: ");
				scanf("%d", &ID);
				fseek(stdin,0,SEEK_END);
				struct Message * temp = search_and_edit_ID (user -> first, ID);
				if (temp != NULL) {
					printf ("   Enter new message: ");
					scanf ("%[^\n]", str);
					free (temp -> msg);
					temp -> msg = (char *) malloc (strlen(str) + 1);
					strcpy (temp -> msg, str);
					printf ("\n   Message edited successfully\n   ");
				}
				else
					printf ("\n   The message you want to edit does not belong to you\n   ");
				system("pause");
				break;
			}
			case 2: break;
			default:
			{
				printf ("\n\n   Wrong choice");
				printf ("\n   It has to be 1 or 2\n   ");
				system("pause");
				break;
			}
		}
	} while (choice != 2);
}
void View_all_messages()
{
	int choice;
	do
	{
		print("view all messages");
		scanf ("%d", &choice);
		switch (choice)
		{
			case 1:
			{
				struct User * temp = first;
				while (temp != NULL)
				{
					print_Messages (temp -> first);
					temp = temp -> next;
				}
				printf ("\n\n   ");
				system("pause");
				break;
			}
			case 2: break;
			default:
			{
				printf ("\n\n   Wrong choice");
				printf ("\n   It has to be 1 or 2\n   ");
				system("pause");
				break;
			}
		}
	} while (choice != 2);
}
void Change_password()
{
	int choice, password;
	do
	{
		print("change password");
		scanf ("%d", &choice);
		switch (choice)
		{
			case 1:
			{
				printf ("\n   Your password must be integer");
				printf ("\n   Enter new password: ");
				scanf ("%d", &password);
				user -> password = password;
				printf ("\n   Password changed successfully ");
				break;
			}
			case 2: break;
			default:
			{
				printf ("\n\n   Wrong choice");
				printf ("\n   It has to be 1 or 2\n   ");
				system("pause");
				break;
			}
		}
	} while (choice != 2);
}
