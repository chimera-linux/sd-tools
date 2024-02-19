project('sd-tools', 'c',
        version : '255',
        license : 'LGPLv2+',
        default_options: [
                'c_std=gnu11',
                'warning_level=3',
        ],
)

cc = meson.get_compiler('c')

possible_common_cc_flags = [
        '-Wno-gnu-statement-expression-from-macro-expansion',
        '-Wno-gnu-zero-variadic-macro-arguments',
        '-Wno-gnu-conditional-omitted-operand',
        '-Wno-zero-length-array',
        '-Wno-unused-parameter',
        '-Wno-language-extension-token',
        '-Wno-c2x-extensions',
        '-Wno-extra-semi',
        '-Wshadow',
        '-fno-strict-aliasing',
        '-fvisibility=hidden',
]

add_project_arguments(
        cc.get_supported_arguments(
                possible_common_cc_flags
        ),
        language : 'c')

librt = cc.find_library('rt')
libm = cc.find_library('m')

libcap = dependency('libcap')
libacl = dependency('libacl', required :get_option('acl'))

conf = configuration_data()

conf.set_quoted('PROJECT_NAME', meson.project_name())
conf.set_quoted('PROJECT_VERSION', meson.project_version())
conf.set10('HAVE_ACL', libacl.found())
conf.set10('HAVE_GSHADOW', cc.has_function('fgetsgent'))
conf.set('_GNU_SOURCE', 1)

config_h = configure_file(
        output: 'config.h',
        configuration: conf)

includes = include_directories('src/shared', '.')

subdir('src/shared')
subdir('src/sysusers')
subdir('src/tmpfiles')

if get_option('tests')
    subdir('test')
endif
