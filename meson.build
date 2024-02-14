# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

project('PKTGEN', 'cpp',
	default_options: ['buildtype=debug'],
)

project_name = 'pktgen'

deps = []
deps += dependency('libdpdk')

machine_args = []

default_cflags = machine_args
cflags = default_cflags

inc_dirs = [
	include_directories('./'),
]

sources = files(
    project_name + '.cc',
    project_name + '-main.cc',
    project_name + '-port-cfg.cc',
    project_name + '-ether.cc',
    project_name + '-ipv4.cc',
    project_name + '-tcp.cc',
    project_name + '-udp.cc',
)

executable(project_name,
        sources,
	    include_directories : inc_dirs,
        dependencies: deps,
        c_args: cflags,
        link_args: ['-lm','-lpthread'],
        install: false)