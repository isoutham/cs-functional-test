#!/bin/sh

sudo ssh -i /root/.ssh/id_rsa.cloud -o StrictHostKeyChecking=no -p 3922 root@$1 ip addr show

