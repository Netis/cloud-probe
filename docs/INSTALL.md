## Linux system

### Prerequisites

* libpcap

### Download
Visit the release page at https://github.com/Netis/cloud-probe/releases, select the appropriate binary package (e.g., cloud-probe-0.9.0-linux-amd64.tar.gz).

### Install

Remove any previous cloud-probe installation by deleting the `/usr/local/cloud-probe` folder (if it exists), then extract the archive you just downloaded into /usr/local, creating a fresh cloud-probe tree in /usr/local/cloud-probe:
```bash
$ rm -rf /usr/local/cloud-probe && tar -C /usr/local -xzf cloud-probe-0.9.0-linux-amd64.tar.gz
```

(You may need to run each command separately with the necessary permissions, as root or through sudo.)

Do not untar the archive into an existing `/usr/local/cloud-probe` tree. This is known to produce broken cloud-probe installations.

Add /usr/local/cloud-probe/bin to the PATH environment variable.
You can do this by adding the following line to your $HOME/.profile or /etc/profile (for a system-wide installation):
```
export PATH=$PATH:/usr/local/cloud-probe/bin
```

Note: Changes made to a profile file may not apply until the next time you log into your computer. To apply the changes immediately, just run the shell commands directly or execute them from the profile using a command such as source $HOME/.profile.

Verify that you've installed cloud-probe by opening a command prompt and typing the following command:
```bash
$ cpworker -v
$ cpdaemon version
```

Confirm that the command prints the installed version of cloud-probe components.
