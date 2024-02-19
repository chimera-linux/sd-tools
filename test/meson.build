test(
    'test-tmpfiles',
    find_program('test-tmpfiles.py'),
    args: exe_tmpfiles.full_path(),
    depends: exe_tmpfiles
)

test(
    'test-sysusers',
    find_program('test-sysusers.sh'),
    args: [exe_sysusers.full_path(), meson.current_source_dir()],
    depends: exe_sysusers,
)
