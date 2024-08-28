# shigen

A resource monitor for the local network.

> [!NOTE]
> This is my first ever Rust project. The code is bad, and it's not really
> that much either. I just wanted to try out Rust and see how it works.
> Now that I know I like it, I will definitely revisit this project and
> eventually make it better. Until then, I will not upload any binaries
> or anything. This is just a fun little project for me to learn Rust.

> [!WARNING]
> Only use this on a local network. Never expose it to outside!
> You don't want someone shutting down your computer remotely...

## Installation

```bash
git clone https://github.com/Kex1016/shigen.git
cd shigen
cargo build --release
```

## Usage

```bash
./target/release/shigen
```

### Endpoints

- `/` - Hello World
- `/system` - System Information
  - `/system/shutdown` - Shutdown the system [POST]
  - `/system/reboot` - Reboot the system [POST]
- `/cpu` - CPU Usage
- `/memory` - Memory Usage
- `/network` - Network Usage
- `/disks` - Disk Usage
- `/processes` - Running Processes
  - `/processes?pid=<PID>&signal=<SIG>` - Send a termination signal to a process [POST]
    - `kill` => Kill
    - `term` => Term
    - `int` => Interrupt
    - `quit` => Quit
    - `stop` => Stop
    - `cont` => Continue
    - `hup` => Hangup
    - `usr1` => User1
    - `usr2` => User2
  - *This isn't the best way to do this, but it's the idea I first had. Will refactor.*
- `/temps` - Temperature Information
- `/user/<username>` - User Information

## TODO?

- [ ] Refactor the process signal sending
- [ ] Websocket?