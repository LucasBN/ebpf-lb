# Setting up the project

First, you'll need to compile `libbpf`:

```
cd external/libbpf
OBJDIR=build DESTDIR=install-dir make -C src install
```

You can then compile the eBPF program loader and the load balancer with:

```
make all
```