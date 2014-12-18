def options(opt):
    opt.load('compiler_c gnu_dirs')

def configure(conf):
    conf.load('compiler_c gnu_dirs')

    for header in 'krb5.h limits.h string.h strings.h sys/fcntl.h sys/file.h'.split():
        conf.check(header_name = header, mandatory=False,
                   features='c cprogram')

    conf.check(lib='ssl', uselib_store='SSL')
    conf.check(lib='crypto', uselib_store='SSL')
    conf.check(lib='krb5', uselib_store='KRB5')
    conf.check(lib='k5crypto', uselib_store='KRB5')
    conf.check(lib='com_err', uselib_store='KRB5')
    conf.check(lib='resolv', uselib_store='KRB5')

    conf.write_config_header('src/config.h')


def build(bld):

    defines = ['HAVE_CONFIG_H', 'WRITE_CERT', 'USE_KRB5']
    bld.stlib(source = bld.path.ant_glob('src/lib/*.c', 
                                         excl=['src/lib/res_*.c']), 
              defines = defines, 
              includes = ['src'],
              target = 'kxlib') 

    kx509src = 'kx509.c debug.c getcert.c get_kca_list.c get_realm.c load_dlls.c store_in_cc.c store_tkt.c materialize_cert.c'.split()
    kx509src = ['src/client/'+s for s in kx509src]
    bld.program(source = kx509src,
                includes = ['src', 'src/lib/'],
                defines = defines,
                target='kx509', 
                use='kxlib KRB5 SSL') 

    bld.program(source = 'src/client/kxlist.c',
                includes = ['src', 'src/lib/'],
                defines = defines,
                target='kxlist',
                use='kxlib KRB5 SSL')

