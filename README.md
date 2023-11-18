# Pipeleon
Pipeleon is an automated performance optimization framework for P4-programmable SmartNICs.

It takes a P4 `.json` file as input, converts it into an internal IR, performs optmizations over the IR, and finally converts it to an optimized `.json` file.

The main optimizations Pipeleon supports include:

- Table reordering: Reorder tables to drop packets as early as possible, or to create more opportunities for other optimizations.
- Table merging: Merge small and static tables into a large table to reduce memory accesses.
- Table caching: Cache one or multiple tables to skip complex table matching.
- Pipeline partitioning: Partition the pipeline into hardware ASICs and software and minimize the traffic migration.

Pipeleon can not only optimize P4 programs at compile time based on a provided profile, it can also adapt the optimizations at runtime based on the collected profiles. See our work for more details!

- [Pipeleon (SIGCOMM'23)](https://jxing.me/pdf/pipeleon-sigcomm23.pdf).
- [FlexCore (NSDI'22)](https://jxing.me/pdf/flexcore-nsdi22.pdf).

## Setup

A Vagrantfile has been provided in `${REPOROOT}`, which allows you to deploy the system with on command.

#### Software versions
```
Vagrant 2.2.10
VirtualBox Version: 5.1.38r122592
Guest Additions Version: 6.1.16
```
#### CPU & memory
In the Vagrantfile, we configure the VM to use 8 CPUs and 16GB memory. This is overkilling for most cases. Please consider adjusting the number based on your machine's available resources.

```
vb.cpus = 8
vb.memory = "16384"
```

#### Start VM and login

From `${REPOROOT}`:
```
vagrant up
# The vm uses default user name 'vagrant'. ssh to the VM by
vagrant ssh
```

This will create a Ubuntu-20.04 VM and automatically install our dependency using script `${REPOROOT}/vagrant_setup.sh`.

To setup manually, refer to the setup script here: `${REPOROOT}/vagrant_setup.sh`.

## Unittest

We provide a large set of unit tests covering the system functions comprehensively. See the instructions here to run these tests: `${REPOROOT}/tests/README.md`.

## User guide

We provide a detailed user guide [here](how-to-use.md).

## Examples

`${REPOROOT}/examples` provides several examples of using the system. See its README for more details.

## Development

Install pre-commit to enforce code style consistency and static checks. From `${REPOROOT}`:
```
pip install pre-commit
pre-commit install
```

## Citation

```
@inproceedings {pipeleon-xing,
    author = {Jiarong Xing and Yiming Qiu and Kuo-Feng Hsu and Songyuan Sui and Khalid Manaa and Omer Shabtai and Yonatan Piasetzky and Matty Kadosh and Arvind Krishnamurthy and T. S. Eugene Ng and Ang Chen},
    title = {Unleashing SmartNIC Packet Processing Performance in P4},
    booktitle = {Proc. ACM SIGCOMM},
    year = {2023}
}
```

## License
The code is released under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html).
