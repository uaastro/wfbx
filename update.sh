#!/bin/bash
git pull

./build.sh

#mkdir -p /usr/sbin/wfbx
cp -r ./wfbx_server/* /usr/sbin/wfbx/
cp -r ./bin/* /usr/sbin/wfbx/
cp ./wfbx_server/wfbx.service /etc/systemd/system/

# Start wfb_server service
systemctl daemon-reload
systemctl enable wfbx.service
systemctl start wfbx.service
systemctl status wfbx.service

