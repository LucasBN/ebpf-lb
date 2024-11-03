# Setting up the project

First, you'll need to compile `libbpf`:

```
git submodule update --init --remote --recursive
cd external/libbpf
OBJDIR=build DESTDIR=install-dir make -C src install
```

You can then compile the eBPF program loader and the load balancer with:

```
make all
```

In order to emulate different servers, we're going to manually setup the network
topology using a linux bridge and network namespaces