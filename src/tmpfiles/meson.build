exe_tmpfiles = executable(
        'sd-tmpfiles', [
                'tmpfiles.c',
                'offline-passwd.c',
        ],
        include_directories: includes,
        link_with: [libshared],
        dependencies: [libacl],
        install: true,
)
