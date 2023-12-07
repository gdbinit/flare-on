This is a [Unicorn Engine](https://www.unicorn-engine.org) based emulator to solve Flare-On 2023 #12 challenge.

To use this you need to modify the code where it says *CHANGE ME* and compile it on each run.

Essentially run it at least two times and a third to run through the verification routine and prove everything is correct.

The code could be modified to do all this by itself but I opted to kept it the same way I tested and solved the challenge.

Check the slides available in the same repo for step by step solution to this challenge.

Technically the whole challenge could have been emulated with Unicorn by patching the Windows Hypervisor API calls and redirecting everything to Unicorn since Unicorn supports the IN/OUT hooks.

Tested on macOS Intel/ARM and Linux.

Have fun,  
fG!
