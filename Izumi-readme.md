# IZUMI Development Notes

### Configuring `runsc` as Docker Runtime 

To get started, first ensure `runsc` is installed as docker runtime. This can be verified by trying 
```
docker run --runtime=runsc --rm hello-world
````


Since we want to be able to debug, we want to make sure the debugging is enabled. 

```
docker run --runtime=runsc-debug --rm hello-world
# If the command above fails, perform the following installation

sudo runsc install --runtime runsc-debug -- \
--debug \
--debug-log=/tmp/runsc-debug.log \
--strace \
--log-packets
```

### Making changes and running the modified `runsc`

To make the build and run quicker, the necessary build, clean and replace commands are saved into `run.sh` in the root folder for the `Izumi` project.
Make the `run.sh` executable.
```
chmod +x run.sh # Run once
```

For all eventual build and run of the modifications in the codebase, just execute the script as:
```
./run.sh 
```

### Testing modifications

Since we are using the `runsc-debug` runtime, all the logs is saved in `/tmp/runsc-debug.log`. 

Start a terminal instance that emits the logs from Izumi modifications by running
```
tail -f /tmp/runsc-debug.log | grep "IZUMI"
```

On another terminal instance, create/run/start the container and perform your tests. 

```
docker run --runtime=runsc-debug --rm -it alpine /bin/sh
```

### Izumi Updates Tracker
- [x] Modify `dmesg` message to announce `IZUMI` modifications
    
    - Verify running `dmesg` in any container run via `runsc-debug`
    - Modifications made in `pkg/sentry/kernel/syslog.go`

- [x] Load a config file

    - The file `/tmp/izumi-config.yaml` if present, is displayed when the container shell is accessed. 
    - Modifications made in 
        - `runsc/config/config.go` to add a configuration field, 
        - `runsc/config/flags.go` to add a flag to handle the configuration filepath,
        - `runsc/cli/main.go` to display that the flag worked and can read the config file

- [x] Attempt a network packet filtering

    - Any network requests from `192.168.0.4` are dropped. 
    - Modifications made in `pkg/tcpip/network/ipv4/ipv4.go` to check if received packet is from the address and to drop accordingly.
    - Verify by starting two containers (IPs assigned by default are 192.168.0.3 and 192.168.0.4) and running `ping 192.168.0.3` from the second container.
        - Ping won't get acknowledged, and the `tail` command with `IZUMI` logs will have message displaying that the packets were dropped. 

- [x] Place Scaffolding for secure container-to-container networking features

    - Added a `--enable-izumi` flag for runsc configuration to enable this
    - Modified TCP protocol implementation to be Izumi-aware with basic logging for verification
    - Network functionalities kept intact and non-intrusive monitoring of TCP connections works

