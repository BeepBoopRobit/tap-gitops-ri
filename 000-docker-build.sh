#!/usr/bin/env bash

if [ -z "$1" ]
  then
    echo "No argument supplied.  Please provide a TANZU NET UAA API TOKEN (a.k.a. Refresh Token) from network.tanzu.vmware.com"
fi


pivnet_api_token=$1

docker build --build-arg PIVNET_API_TOKEN="${pivnet_api_token}" -t tap-installer:latest .

docker volume create tanzu-workdir
git clone git@github.com:BeepBoopRobit/tap-gitops-ri.git
# mount cloned git repo 
docker run --rm -it -v /home/tanzu/tap-gitops-ri:/app tap-installer:latest bash