# Tanzu GitOps Reference Implementation (WIP)

## Getting Started Quick

Run the docker build script
```000-docker-build.sh```

Fork the repo and update the ```01-setup.sh``` on Line 171 with your repo.

Create the ```values.yaml``` from the ```values-template.yaml``` file.

```
$ cp ./config/templates/values-template.yaml ./config/values.yaml
```

Then, update the ```./config/values.yaml``` file for TAP values.

If you need to create required certificates:
```
$ ./00-airgapped-prep.sh gen-cert
```

For airgapped environments, run the ```00-airgapped-prep.sh``` script.

Downloading required all packages.
```
$ ./00-airgapped-prep.sh prep
```

Importing required all CLIs
```
$ ./00-airgapped-prep.sh import-cli
```

Importing required all packages.
```
$ ./00-airgapped-prep.sh import-packages
```

Then run the ```01-setup.sh``` for installation
```
$ ./01-setup.sh
```

Finally, run the post install command.
```
$ ./00-airgapped-prep.sh post-install
```
