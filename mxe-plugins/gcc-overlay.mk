# MXE defaults to Win7 now <https://github.com/mxe/mxe/pull/2785>
#TODO: Check mxe/src/gcc.mk changes on updates

gcc_BUILD_i686-w64-mingw32 = \
    $(subst --with-default-msvcrt=msvcrt ,--with-default-msvcrt=msvcrt-os ,\
    $(subst --with-default-win32-winnt=0x0601 ,--with-default-win32-winnt=0x0502 ,\
    $(subst @gcc-crt-config-opts@,--disable-lib64,$(gcc_BUILD_mingw-w64))))
gcc_BUILD_x86_64-w64-mingw32 = \
    $(subst --with-default-msvcrt=msvcrt ,--with-default-msvcrt=msvcrt-os ,\
    $(subst --with-default-win32-winnt=0x0601 ,--with-default-win32-winnt=0x0502 ,\
    $(subst @gcc-crt-config-opts@,--disable-lib32,$(gcc_BUILD_mingw-w64))))

