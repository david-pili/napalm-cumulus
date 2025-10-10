# napalm-cumulus

This is a [NAPALM](https://napalm.readthedocs.io/en/latest/) driver for cumulus linux through ssh.

This is a fork of https://github.com/justinbrink/napalm-cumulus with updates for Cumulus 5 and nvue. Tested on Cumulus 5.12

## Install

There is no PyPi repo, to install use command line:

```shell
pip install git+https://github.com/david-pili/napalm-cumulus.git@master
```

## Usage

you can use this new driver, example with napalm command line:

```shell
napalm --user myuser --vendor cumulus my-mellanox.switch.company.com call get_interfaces
```
