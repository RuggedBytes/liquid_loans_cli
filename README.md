# CLI tools for "Asset-Based Lending smart contract for Liquid network"

This is the source code for the CLI tools that implement the wokrings of
the smart contract described in the article at
[https://ruggedbytes.com/articles/ll/](https://ruggedbytes.com/articles/ll/) --
"Asset-Based Lending smart contract for Liquid network".

The code here is intended for demonstration and research purposes, and the environment
of the docker image is set up to work with 'liquidregtest' network, which is not a real
Liquid network.

It should be possible to run with real Liquid network by specifying `liquidv1` for
the `--network` argument of the tools, but those who will do it should know that they
are doing and that they doing it at their own risk (risk for their funds).

# No detailed help

For now, there's no detailed descriptions of the tools or their command-line arguments.

Those interested are encouraged to study the article linked above, and then the source code
of the tools (including the code of the tests which have examples of running the tools),
and can also run GUI demo programs that can be found at
[https://github.com/RuggedBytes/liquid_loans_gui_demo](https://github.com/RuggedBytes/liquid_loans_gui_demo).

When executing these CLI tools, the GUI demo programs print the command to the terminal
with all their arguments. This way you can observe how CLI tools have to be run and with
what arguments and at what stage of the contract.

You can also refer to built-in help that the CLI tools give out with the `--help` argument.

# Experimental code

At the moment of release, the code for the CLI tools have received more attention in
regards of the quality of code and testing than the GUI demo tools;
The code passes mypy typechecking with --strict option. It is still not have been used
in live Liquid network at the time of the release, and is therefore its status should be
considered an experimental code with all what this implies.

# How to run

## Build the docker image

`docker build -f devel/Dockerfile -t loans_test .`

## Run the docker image

`docker run -it --rm --name loans_test -v $(pwd):/root/scripts loans_test /bin/bash`

The environment will have two Elements daemons running, and you will find the CLI tools
under `/root/scripts`. You can use `/root/elementsdir1/elements.conf` or
`/root/elementsdir2/elements.conf` for the `-r` argument of the CLI tools (you can
also specify the url directly in the form of `http://user:password@url` for `-r`)

Note that translating the current directory with `-v $(pwd):/root/scripts` into the
container and running the CLI tools there under root might result in some root-owned
files on the host within the directory, but this way is more convenient for development
and experimentation since you can edit the files on the host and run inside the container
right away. If it does not suit you, please edit the Dockerfile to copy the source
inside the container.
