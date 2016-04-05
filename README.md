# PF Trace

PF Trace is a C / C++ trace infrastructure written in C. It was designed with the aim to be as easy to use as printf/syslog while being as fast and efficient as a binary tracer. The trace infrastracture is lock free and avoids acquiring locks or doing I/O on the expence on the calling thread. Instead the trace information is queued into a lock free queue in a binary form and is written by a separate thread.

## Usage Example
```
	pf_trace_config_t trace_cfg = PF_TRC_DEFAULT_INIT;
	int res = pf_trace_init(&trace_cfg);
	assert(res == 0);

	trcntc("hello world");

	pf_trace_destroy();
```

## How fast is it?
This loop, tracing 1 million messages takes ~200 milliseconds on my Cento7 VM running on top of a Macbook Pro.

```
	for (i = 0; i < 1000000; i++) {
		trcntc("i=%d", i);
	}
```

~0.2 microsecond per message.

## Reading a trace file
Since the file is written in a binary form you need the trace reader utility in order to read it. Each trace session creates 2 new files, a .md file that stores the trace messages meta data and a .trc file that stores the trace messages. The process pid is attached to the file name in order to differntiate between the sessions. In addition a symlink is created pointed to the latest trace file.

Reading the output of the usage example gives the following output:

```
	./src/pf-trace-reader ./pf_trace.latest.trc
```

```
	2016-04-05 14:17:48.370174299 (39340) [NTC] pf_trace_test.c:67 basic_test() hello world
```

## Using the pf trace daemon
Since the trace message don't go directly to disk there is a risk of loosing the in flight messages in case of a crash. Unfortunately these are usually the messages that interest us the most. In order to avoid the message loss there is an option to place the trace queue in shared memory and have a daemon process write these messages instead of a thread contained in the process being traced. To use that option simply run the pd-trace-daemon process and set the **use_trace_daemon** daemon flag in the trace configuration to true.

## Build Instructions
Install lf-queue "https://github.com/asaf-levy/lockfree-queue"

1. Install CMake
2. mkdir build
3. cd build
4. cmake ../
5. make

Run tests with "make test"
To install run "make install" 
