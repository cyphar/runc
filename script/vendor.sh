#!/bin/bash

# This is inspired by Docker's hack/vendor.sh script, except that this uses
# govendor rather than Docker's magical shell functions.

if ! (which govendor &>/dev/null)
then
cat >&2 <<EOF
You must have govendor installed in order to update the vendor list. You can get
the tool by following the instructions here:

                     https://github.com/kardianos/govendor

Or by running the following command:

                    go get -u github.com/kardianos/govendor
EOF
	exit 1
fi

function fetch() {
	local repo="${1}"
	local rev="${2}"

	echo "FETCH ${repo}:${rev}"

	# If the revision starts with a "v" then we have to prepend "=" to ensure
	# we get version pinning. Otherwise govendor will decide to pull the latest
	# version based on semver.
	if (grep "^v" <(echo "${rev}") &>/dev/null)
	then
		rev="=${rev}"
	fi

	govendor fetch "${repo}@${rev}"
}

function setup() {
	# Remove and setup vendor directory.
	rm -rf vendor/*
	govendor init
}

setup

fetch github.com/Sirupsen/logrus 26709e2714106fb8ad40b773b711ebce25b78914
fetch github.com/urfave/cli edb24d02aa3cea2319c33f2836d4a5133907fe4c
fetch github.com/coreos/go-systemd/activation v4
fetch github.com/coreos/go-systemd/dbus v4
fetch github.com/coreos/go-systemd/util v4
fetch github.com/docker/docker/pkg/mount 0f5c9d301b9b1cca66b3ea0f9dec3b5317d3686d
fetch github.com/docker/docker/pkg/symlink 0f5c9d301b9b1cca66b3ea0f9dec3b5317d3686d
fetch github.com/docker/docker/pkg/term 0f5c9d301b9b1cca66b3ea0f9dec3b5317d3686d
fetch github.com/docker/go-units v0.1.0
fetch github.com/godbus/dbus v3
fetch github.com/golang/protobuf/proto f7137ae6b19afbfd61a94b746fda3b3fe0491874
fetch github.com/opencontainers/runtime-spec/specs-go v1.0.0-rc1
fetch github.com/seccomp/libseccomp-golang 60c9953736798c4a04e90d0f3da2f933d44fd4c4
fetch github.com/syndtr/gocapability/capability 2c00daeb6c3b45114c80ac44119e7b8801fdd852
fetch github.com/vishvananda/netlink 1e2e08e8a2dcdacaae3f14ac44c5cfa31361f270
