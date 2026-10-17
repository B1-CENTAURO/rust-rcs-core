#!/bin/sh
# Copyright 2023 宋昊文
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Makes DIR/venv, a Python with msrplib and what it needs, at the versions
# tests/msrp_interop.rs was run with. Needs python3 (3.13 was used), git and
# libgnutls; prints the MSRPLIB_PYTHON to run the tests with.
#
#   interop/msrplib/setup.sh DIR

set -eu

dir=${1:?usage: setup.sh DIR}
mkdir -p "$dir/src"
dir=$(cd "$dir" && pwd)

clone() {
    if [ ! -d "$dir/src/$1" ]; then
        git clone -q "https://github.com/AGProjects/$1" "$dir/src/$1"
    fi
    git -C "$dir/src/$1" checkout -q "$2"
}

clone python3-application a36a54acab8e48e059df87bd2673e651f599d5e6
clone python3-eventlib ed036afa4d462251f5cd7584c6f6ec6c9948e4d5
clone python3-gnutls 24095ed3daf774304c2d1f68c735ce919ca6178f
clone python3-msrplib 212417df9b21b56eaf9cfae4ebf625cbda7ecf90 # 0.21.3

python3 -m venv "$dir/venv"
pip="$dir/venv/bin/pip"
"$pip" install -q setuptools==84.0.0 wheel==0.48.0 \
    Twisted==26.4.0 zope.interface==8.7 greenlet==3.5.6
for package in python3-application python3-gnutls python3-eventlib python3-msrplib; do
    "$pip" install -q --no-build-isolation "$dir/src/$package"
done

(cd "$dir" && venv/bin/python -I -c 'import msrplib.session')
echo "MSRPLIB_PYTHON=$dir/venv/bin/python"
