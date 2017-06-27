#!/bin/bash
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

set -e

usage() {
	echo "install_z3_yices.sh download_dir install_dir"
	exit 1
}

if [ "$#" -ne "2" ]; then
	usage
fi

DOWNLOAD_DIR=$1
INSTALL_DIR=$2

mkdir -p $DOWNLOAD_DIR
cd $DOWNLOAD_DIR

#download z3 and yices
curl https://saw.galois.com/builds/z3/z3 > z3
curl https://saw.galois.com/builds/yices/yices_smt2-linux-static > yices-smt2
sudo chmod +x z3
sudo chmod +x yices-smt2
mkdir -p $INSTALL_DIR/bin
mv z3 $INSTALL_DIR/bin
mv yices-smt2 $INSTALL_DIR/bin
$INSTALL_DIR/bin/z3 --version
$INSTALL_DIR/bin/yices-smt2 --version