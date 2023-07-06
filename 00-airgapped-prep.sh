#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 gen-cert|prep|import-packages|post-install"
    exit 1
fi

# Assumptions:
# Harbor is deployed
# Nexus is deployed
# Git Server is deployed 
# TKGS Supervisor is deployed
# We have a vSphere WCP Namespace we can use to deploy a TKG Cluster
# We are running on a bastion with internet access
# User has a VMW Community login, TanzuNet login and has accepted Tanzu EULAs
# User has a vsphere login that can do 'kubectl vsphere login'
# User has a Git login (http/web and ssh for clone)
# User can edit DNS
# We have a wildcard cert for our TAP domain

# TODOs:
# remove Minio and plan to use Nexus.  Also Assume a Nexus is up.  We can use the container to start?
# plan to install tools on an AlmaLinux docker image
# tools to install:
# tanzu
# Kubectl ? or should we get this from Supervisor

# Overview
# get kubectl vsphere plugin
# kubectl config use-context <supervisor-context>
# kubectl apply -f <new-tap-cluster>
# kubectl config use-context <tap-cluster>
# init tanzu cli - https://docs.vmware.com/en/VMware-Tanzu-Application-Platform/1.4/tap/install-tanzu-cli.html#install-or-update-the-tanzu-cli-and-plugins-3
# 

BLOBSTORE_URL=$(yq eval '.blobstore_url' ./config/values.yaml)
CLUSTER_ESSENTIALS_VERSION=$(yq eval '.cluster_essentials_version' ./config/values.yaml)
HARBOR_URL=$(yq eval '.image_registry' ./config/values.yaml)
HARBOR_USERNAME=$(yq eval '.image_registry_user' ./config/values.yaml)
HARBOR_PASSWORD=$(yq eval '.image_registry_password' ./config/values.yaml)
HARBOR_TAP_REPO=$(yq eval '.image_registry_tap' ./config/values.yaml)
IMGPKG_REGISTRY_HOSTNAME_0=registry.tanzu.vmware.com
IMGPKG_REGISTRY_USERNAME_0=$(yq eval '.tanzuNet_username' config/values.yaml)
IMGPKG_REGISTRY_PASSWORD_0=$(yq eval '.tanzuNet_password' config/values.yaml)
IMGPKG_REGISTRY_HOSTNAME_1=$(yq eval '.image_registry' ./config/values.yaml)
IMGPKG_REGISTRY_USERNAME_1=$(yq eval '.image_registry_user' ./config/values.yaml)
IMGPKG_REGISTRY_PASSWORD_1=$(yq eval '.image_registry_password' ./config/values.yaml)
IMGPKG_REGISTRY_HOSTNAME=$(yq eval '.image_registry' ./config/values.yaml)
IMGPKG_REGISTRY_USERNAME=$(yq eval '.image_registry_user' ./config/values.yaml)
IMGPKG_REGISTRY_PASSWORD=$(yq eval '.image_registry_password' ./config/values.yaml)
INGRESS_DOMAIN=$(yq eval '.ingress_domain' ./config/values.yaml)
TAP_VERSION=$(yq eval '.tap_version' ./config/values.yaml)
TBS_VERSION=$(yq eval '.tbs_version' ./config/values.yaml)

#export INGRESS_DOMAIN BLOBSTORE_URL HARBOR_URL HARBOR_USERNAME HARBOR_PASSWORD HARBOR_TAP_REPO 
WORKSPACE="$HOME/workspace" #.$(date +'%s')/" TODO: flip this back once we're done iterating.  Doing this now to save time by not re-downloading images
mkdir -p "$WORKSPACE"

#let's just get the registry cert
echo -n | openssl s_client -connect "${IMGPKG_REGISTRY_HOSTNAME_1}:443" -showcerts 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > "${WORKSPACE}/registry.crt"

REGISTRY_CA_PATH="${WORKSPACE}/registry.crt"
export TAP_PKGR_REPO=$IMGPKG_REGISTRY_HOSTNAME_1/tap-packages/tap

function declare_harbor_project() {
  repo_name=$1
  curl -u "${HARBOR_USERNAME}:${HARBOR_PASSWORD}" \
    -X POST \
    -H "content-type: application/json" \
    "https://${HARBOR_URL}/api/v2.0/projects" \
    -d "{\"project_name\": \"${repo_name}\", \"public\": true, \"storage_limit\": -1 }" \
    --ca-cert "${REGISTRY_CA_PATH}"
}
function imgpkg_dl() {
  _pkg=$1
  _tar=$2
  if [ ! -e "${_tar}" ]; then
  imgpkg copy \
    -b "${_pkg}" \
    --to-tar "${_tar}" \
    --include-non-distributable-layers \
    --concurrency 30
else
  echo "Found ${_tar}...skipping download"
fi
}
##upload local tar to a repo
function imgpkg_ul() {
  _tar=$1
  _repo=$2
  _repo_ca_path=$3
  imgpkg copy \
  --tar "${_tar}" \
  --to-repo "${_repo}" \
  --include-non-distributable-layers \
  --concurrency 30 \
  --registry-ca-cert-path "${_repo_ca_path}"

}
cd "$WORKSPACE" || exit

# check the first parameter
if [ "$1" = "prep" ]; then
    echo "start prepping files...."

    mkdir -p airgapped-files/
    pushd airgapped-files/ || exit
    
    # echo "Downloading age"
    # wget -q https://github.com/FiloSottile/age/releases/download/v1.1.1/age-v1.1.1-linux-amd64.tar.gz && tar -xvf age-v1.1.1-linux-amd64.tar.gz
    
    # echo "Downloading sops"
    # wget -q https://github.com/mozilla/sops/releases/download/v3.7.3/sops-v3.7.3.linux.amd64 && chmod +x sops-v3.7.3.linux.amd64

    # echo "Downloading charts-syncer"
    # uname -s| grep Linux && wget -q https://github.com/bitnami-labs/charts-syncer/releases/download/v0.20.1/charts-syncer_0.20.1_linux_x86_64.tar.gz && tar -xvf charts-syncer_0.20.1_linux_x86_64.tar.gz && cp charts-syncer /usr/local/bin/charts-syncer
    # uname -s| grep Darwin && wget -q https://github.com/bitnami-labs/charts-syncer/releases/download/v0.20.1/charts-syncer_0.20.1_darwin_x86_64.tar.gz && tar -xvf charts-syncer_0.20.1_darwin_x86_64.tar.gz && cp charts-syncer /usr/local/bin/charts-syncer
    
    # imgpkg binary check
    if ! command -v imgpkg >/dev/null 2>&1 ; then
      echo "installing imgpkg"
      tar -xvf tanzu-cluster-essentials*.tgz
      cp imgpkg /usr/local/bin/imgpkg
    fi
    
    docker login registry.tanzu.vmware.com -u "${IMGPKG_REGISTRY_USERNAME_0}" -p "${IMGPKG_REGISTRY_PASSWORD_0}"
    
    echo "Downloading TAP Packages"
    imgpkg_dl "${IMGPKG_REGISTRY_HOSTNAME_0}/tanzu-application-platform/tap-packages:${TAP_VERSION}" "tap-packages-${TAP_VERSION}.tar"
    
    echo "Downloading TBS Full Dependencies"
    imgpkg_dl "${IMGPKG_REGISTRY_HOSTNAME_0}/tanzu-application-platform/full-tbs-deps-package-repo:$TBS_VERSION" tbs-full-deps.tar 
    
    echo "Downloading Cluster Essentials" # can we get this by an actual tag instead of the sha256?
    imgpkg_dl "${IMGPKG_REGISTRY_HOSTNAME_0}/tanzu-cluster-essentials/cluster-essentials-bundle@sha256:a119cb90111379a5f91d27ae572a0de860dd7322179ab856fb32c45be95d78f5" "cluster-essentials-bundle-${CLUSTER_ESSENTIALS_VERSION}.tar" \
      
    echo "Downloading Grype Vulnerability Definitions"
    wget -q https://toolbox-data.anchore.io/grype/databases/listing.json
    jq --arg v1 "$v1" '{ "available": { "1" : [.available."1"[0]] , "2" : [.available."2"[0]], "3" : [.available."3"[0]] , "4" : [.available."4"[0]] , "5" : [.available."5"[0]] } }' listing.json > listing.json.tmp
    mv listing.json.tmp listing.json
    wget -q $(cat listing.json |jq -r '.available."1"[0].url')
    wget -q $(cat listing.json |jq -r '.available."2"[0].url')
    wget -q $(cat listing.json |jq -r '.available."3"[0].url')
    wget -q $(cat listing.json |jq -r '.available."4"[0].url')
    wget -q $(cat listing.json |jq -r '.available."5"[0].url')
    sed -i -e "s|toolbox-data.anchore.io|$BLOBSTORE_URL|g" listing.json
    
    echo "Downloading tool images"
    export tool_images=$(cat /app/config/templates/tools/*.yaml|grep "image: "|awk '{ print $2 }')
    mkdir -p images
    for image in $tool_images
    do
        echo $image
        export tool=$(echo $image | awk -F'/' '{print $(NF)}')
        imgpkg copy -i $image --to-tar=images/$tool.tar
        # do something with the image
    done
# do we want to just take these from the actual vmware repos instead?  TODO: point to VMW or figure out what changed
    #git clone https://github.com/configozlu/weatherforecast-steeltoe-net-tap && rm -rf weatherforecast-steeltoe-net-tap/.git
    #git clone https://github.com/configozlu/tanzu-java-web-app && rm -rf tanzu-java-web-app/.git
    #git clone https://github.com/configozlu/node-express && rm -rf node-express/.git
    #git clone https://github.com/MoSehsah/bank-demo && rm -rf bank-demo/.git
    
#     echo "Downloading Bitnami Catalog"
# cat > 01-bitnami-to-local.yaml <<-EOF
# source:
#   repo:
#     kind: HELM
#     url: https://charts.app-catalog.vmware.com/demo
# target:
#   intermediateBundlesPath: bitnami-local
# charts:
# - redis
# - mysql
# - rabbitmq
# - postgresql
# EOF
#     charts-syncer sync --config 01-bitnami-to-local.yaml --latest-version-only
    
    popd || exit #back to workspace dir

# elif [ "$1" = "import-cli" ]; then
#     echo "start importing clis...."

#     pushd airgapped-files/ || exit

#     # age
#     if ! command -v age >/dev/null 2>&1 ; then
#       echo "installing age"
#       wget -q https://github.com/FiloSottile/age/releases/download/v1.1.1/age-v1.1.1-linux-amd64.tar.gz && tar -xvf age-v1.1.1-linux-amd64.tar.gz
#       install age/age /usr/local/bin/age && install age/age-keygen /usr/local/bin/age-keygen
#     fi
    
#     # sops
#     if ! command -v sops >/dev/null 2>&1 ; then
#       echo "installing sops"
#       install sops-v3.7.3.linux.amd64 /usr/local/bin/sops
#     fi

#     # kapp
#     if ! command -v kapp >/dev/null 2>&1 ; then
#       echo "installing kapp"
#       tar -xvf tanzu-cluster-essentials*.tgz
#       install kapp /usr/local/bin/kapp
#     fi
    
#     # imgpkg
#     if ! command -v imgpkg >/dev/null 2>&1 ; then
#       echo "installing imgpkg"
#       tar -xvf tanzu-cluster-essentials*.tgz
#       install imgpkg /usr/local/bin/imgpkg
#     fi
  
#     popd || exit

elif [ "$1" = "import-packages" ]; then
    echo "start importing files...."
    #cp "$REGISTRY_CA_PATH" /etc/ssl/certs/tap-ca.crt #what are we doing here?? we have the cert, but we're still doing '-k'??

    declare_harbor_project "${HARBOR_TAP_REPO}"
    declare_harbor_project "tap-packages" #TODO: make this a var
    declare_harbor_project "bitnami" #TODO: make this a var
    declare_harbor_project "tools" #TODO: make this a var
    
    cp airgapped-files/tanzu-gitops-ri-*.tgz .
    cp airgapped-files/tanzu-cluster-essentials*.tgz config/
    
    imgpkg copy \
      --tar "airgapped-files/tap-packages-${TAP_VERSION}.tar" \
      --to-repo "${IMGPKG_REGISTRY_HOSTNAME_1}/tap-packages/tap" \
      --include-non-distributable-layers \
      --concurrency 30 \
      --registry-ca-cert-path "${REGISTRY_CA_PATH}"
    
    imgpkg copy --tar airgapped-files/tbs-full-deps.tar \
      --to-repo="$IMGPKG_REGISTRY_HOSTNAME_1"/tap-packages/tbs-full-deps --concurrency 30 --registry-ca-cert-path "$REGISTRY_CA_PATH"
    
    
    KAPP_NS=$(kubectl get pods --all-namespaces -l app=kapp-controller -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.status.phase}{"\n"}{end}'| awk '{print $1}')
    KAPP_POD=$(kubectl get pods --all-namespaces -l app=kapp-controller -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'| awk '{print $1}')
    
    if [ -n "$KAPP_NS" ]; then
        echo "kapp is running, adding ca.cert"
        kubectl create secret generic kapp-controller-config \
           --namespace $KAPP_NS \
           --from-file caCerts=config/ca.crt
        kubectl delete pod $KAPP_POD -n $KAPP_NS
    else
        echo "kapp is not running, therefore installing."
        kubectl create namespace kapp-controller
        kubectl create secret generic kapp-controller-config \
           --namespace kapp-controller \
           --from-file caCerts=config/ca.crt

        imgpkg_up airgapped-files/cluster-essentials-bundle-"${TAP_VERSION}".tar "$IMGPKG_REGISTRY_HOSTNAME_1"/tap-packages/cluster-essentials-bundle "$REGISTRY_CA_PATH"

        export INSTALL_BUNDLE=$IMGPKG_REGISTRY_HOSTNAME_1/tap-packages/tanzu-cluster-essentials/cluster-essentials-bundle@sha256:79abddbc3b49b44fc368fede0dab93c266ff7c1fe305e2d555ed52d00361b446
        export INSTALL_REGISTRY_HOSTNAME=${IMGPKG_REGISTRY_HOSTNAME_0}
        export INSTALL_REGISTRY_USERNAME=$(yq eval '.tanzuNet_username' config/values.yaml)
        export INSTALL_REGISTRY_PASSWORD=$(yq eval '.tanzuNet_password' config/values.yaml)
        pushd config/tanzu-cluster-essentials || exit 1
        ./install.sh --yes
        popd || exit 1
    fi

    pushd  airgapped-files/ || exit 1
cat > 02-bitnami-from-local.yaml <<-EOF
source:
  intermediateBundlesPath: bitnami-local
target:
  containerRegistry: $HARBOR_URL
  containerRepository: bitnami/containers
  containers:
    auth:
      username: admin
      password: VMware1!
  repo:
    kind: OCI
    url: https://$HARBOR_URL/bitnami/charts
    auth:
      username: $HARBOR_USERNAME
      password: $HARBOR_PASSWORD
EOF
    charts-syncer sync --config 02-bitnami-from-local.yaml
    popd || exit 1

    export tool_images=$(cat config/templates/tools/*.yaml|grep "image: "|awk '{ print $2 }')
    echo $tool_images
    for image in $tool_images
    do
        echo $image
        export tool=$(echo $image | awk -F'/' '{print $(NF)}')
        export tool_name=$(echo $tool | cut -d':' -f1)
        imgpkg copy \
          --tar airgapped-files/images/$tool.tar \
          --to-repo $IMGPKG_REGISTRY_HOSTNAME_1/tools/tools/$tool_name \
          --include-non-distributable-layers \
          --registry-ca-cert-path $REGISTRY_CA_PATH
        sed -i -e "s~$image~$IMGPKG_REGISTRY_HOSTNAME_1\/tools\/tools\/${tool}~g" config/templates/tools/*.yaml
        rm -f config/templates/tools/*.yaml-e
    done

elif [ "$1" = "post-install" ]; then
    #TODO: when is Nexus deployed?  
    export nexus_init_pass=$(kubectl exec -it $(kubectl get pod -n nexus -l app=nexus -o jsonpath='{.items[0].metadata.name}') -n nexus -- cat /nexus-data/admin.password)
    curl -u "admin:${nexus_init_pass}" -X 'PUT' "https://nexus-80.$INGRESS_DOMAIN/service/rest/v1/security/users/admin/change-password" -H 'accept: application/json' -H 'Content-Type: text/plain' -d ${HARBOR_PASSWORD} -k
    curl -u "admin:${HARBOR_PASSWORD}" -X 'PUT' "https://nexus-80.$INGRESS_DOMAIN/service/rest/v1/security/anonymous" -H 'accept: application/json' -H 'Content-Type: text/plain' -d '{"enabled": true, "userId": "anonymous", "realmName": "NexusAuthorizingRealm"}' -k
    curl -u "admin:${HARBOR_PASSWORD}" -X 'POST' "https://nexus-80.$INGRESS_DOMAIN/service/rest/v1/repositories/npm/proxy" -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"name": "npm","online": true,"storage": {"blobStoreName": "default","strictContentTypeValidation": true,"writePolicy": "ALLOW"},"cleanup": null,"proxy": {"remoteUrl": "https://registry.npmjs.org","contentMaxAge": 1440,"metadataMaxAge": 1440},"negativeCache": {"enabled": true,"timeToLive": 1440},"httpClient": {"blocked": false,"autoBlock": true,"connection": {"retries": null,"userAgentSuffix": null,"timeout": null,"enableCircularRedirects": false,"enableCookies": false,"useTrustStore": false},"authentication": null},"routingRuleName": null,"npm": {"removeNonCataloged": false,"removeQuarantined": false},"format": "npm","type": "proxy"}' -k
    curl -u "admin:${HARBOR_PASSWORD}" -X 'POST' "https://nexus-80.$INGRESS_DOMAIN/service/rest/v1/security/users" -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"userId": "tanzu","firstName": "tanzu","lastName": "tanzu","emailAddress": "tanzu@vmware.com","password": "VMware1!","status": "active","roles": ["nx-admin"]}' -k

# we're not doing minio, so this needs to be curl with PUTs?
    mc alias set minio https://$BLOBSTORE_URL minio minio123 --insecure
    mc mb minio/grype --insecure
    mc cp airgapped-files/vulnerability*.tar.gz minio/grype/databases/ --insecure
    mc cp airgapped-files/listing.json minio/grype/databases/ --insecure
    mc anonymous set download minio/grype --insecure

elif [ "$1" = "gen-cert" ]; then
    mkdir -p cert/
    cd cert
    export DOMAIN=*.$INGRESS_DOMAIN
    
    export SUBJ="/C=TR/ST=Istanbul/L=Istanbul/O=Customer, Inc./OU=IT/CN=${DOMAIN}"
    openssl genrsa -des3 -out ca.key -passout pass:1234 4096
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -passin pass:1234 -addext "keyUsage=critical, digitalSignature, cRLSign, keyCertSign" -addext "basicConstraints=critical,CA:true" -out ca.crt -subj "$SUBJ"
    openssl genrsa -out server-app.key 4096
    openssl req -sha512 -new \
          -subj "$SUBJ" \
          -key server-app.key \
          -out server-app.csr
cat > v3.ext <<-EOF
  authorityKeyIdentifier=keyid,issuer
  basicConstraints=CA:FALSE
  keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
  extendedKeyUsage = serverAuth
  subjectAltName = @alt_names
  [alt_names]
  DNS.1=${DOMAIN}
EOF
    openssl x509 -req -sha512 -days 3650 \
          -passin pass:1234 \
          -extfile v3.ext \
          -CA ca.crt -CAkey ca.key -CAcreateserial \
          -in server-app.csr \
          -out server-app.crt
    openssl rsa -in ca.key -out ca-no-pass.key -passin pass:1234
    cd ..
else
    echo "Invalid parameter: $1"
    exit 1
fi

