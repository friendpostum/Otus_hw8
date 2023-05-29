# bayan

Find file duplicates

## Arguments

-h [ --help ] &emsp; &emsp; &emsp; &emsp; &emsp; &emsp; &emsp;Help message\
-H [ --hash ] arg (=crc32) &emsp;&emsp;&ensp; A hashing algorithm crc32/ md5/ sha1\
-d [ --dir_scan ] arg  &emsp; &emsp; &emsp; &emsp; Directories to scanning\
-e [ --dir_skip ] arg  &emsp;&emsp;&emsp;&emsp; &emsp; Directories excluded\
-m [ --masks ] arg  &emsp;&emsp; &emsp; &emsp;&emsp; Regular expression mask, \
-l [ --depth ] arg (=1)&emsp; &emsp; &emsp; &emsp; 0-only specified directory / 1-all nested\
-s [ --file_min_sz] arg (=1)     &emsp; &emsp;Minimum file size, byte\
-S [ --block_sz ] arg (=1)      &emsp;&emsp;&emsp;Reading block size, byte



```
--help,-h           Print help information.

--hash,-H           A hash algorithm. Supported values are: crc32 (default) and md5.

--dir_scan,-d       One or more paths to be scanned. If not specified, the scan starts in the current directory.
                     Example:
                     -d /absolute/path ../relative/path

--dir_skip,-e       One or more paths which must not be scanned.
                     Example:
                     -e /absolute/path ../relative/path
--masks, -n         File name pattern.              
                     Special characters:
                      *   Any zero or more characters.
                      ?   Any one character.
                      \   Removes special meaning of '?'. E.g.: \? means 'a question mark' (not a wildcard).

--depth,-l          A subdirectory level. E.g. 0 (default value) means that only the current directory must be scanned. 1 - the current directory and its subdirectories. And so on.

--file_min_sz,-s    A minimum file size. Files which are smaller than the specified size will be skipped. The default value is 2.




--block_sz, -S     A number of bytes which are read per one I/O operation. The default value is 8.             
```