# SOA-project

## Specification
For project specification refer to the [Project Specification](https://francescoquaglia.github.io/TEACHING/AOS/AA-2023-2024/PROJECTS/project-specification-2023-2024.html).

## Usage

To clone the repository:

```bash
git clone https://github.com/MicheleTosi/SOA-project.git
cd SOA-project
```

After this run `sudo ./start.sh` to install the reference monitor module and the single-fs file system.

To shut down reference monitor and the single-fs run `sudo ./stop.sh`.

To interact with the module we can use:

- user.c `sudo ./user/user`
- tests `sudo ./tests/test`

Default password is: "password".

## User
To interact with reference monitor run:

```
sudo ./user/user
```

The following commands can be executed:

- start: start the reference monitor (state ON)
- stop: stop the reference monitor (state OFF)
- reconfig_on: start reference monitor in reconfig mode
- reconfig_off: stop the reference monitor in reconfig mode
- status: show current status
- set-password: change password
- add-path [path]: add a new protected path
- remove-path [path]: remove a protected path
- print-logs: list events log

## Tests
Tests provide a simple way to interact with the project.

To execute tests run: 

```bash
cd tests
sudo ./tests
```

This application creates a test environment, protects a file and a directory and tries to execute the probed system calls (`create`, `open`, `unlink`, `mkdir`, `rmdir`).
