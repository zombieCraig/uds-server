UDS Server
==========

Unified Diagnostic Services (UDS) Server - is a ECU simulator that provides UDS support.
This application was originally written to go alongside of [ICSim] (https://github.com/zombieCraig/ICSim)
for training.

Running both ICSim and uds-server can give students a more realistic use of tools.  You can use
ICSim to understand the basics of reversing CAN and uds-server to dig into the UDS protocol
and Engine Control Unit (ECU) inspections such as memory reads and device I/O controls via the ECU instead of spoofed
Controller Area Network (CAN bus) packets.

In addition, when developing uds-server, it showed several more uses.  When a dealership tool
is known to uds-server, it makes it very easy to see what the tool is attempting to do by spoofing
a real target vehicle.  This allows you to quickly reverse commands from dealership tools and
see only the packets that matter.  Another nice feature, is the ability to fuzz the
dealership/scantools to see if they are doing proper input validation checks.  This enables
uds-server to work as a security tool by playing the role of a modified "malicious" vehicle and
seeing how the shop's tools handle the malformed requests.


Compiling uds-server
====================

Right now the tool was developed on Ubuntu Linux but is simple enough that it should compile on
any standard Linux system.  Simply type 'make':

```
$ make
cc     uds-server.c   -o uds-server
```

This version is still considered 'alpha' but the help screen should look something like:

```
Simulates UDS responses
Usage: ./uds-server [options] <can_interface>
	-z		Increase fuzz level
	-v		Verbose
	-l <logfile>	Log output to file instead of STDOUT
	-c		Don't fuzz ISOTP Spec, just data
	-F		Disable flow control (Functional Addressing)
	-V <vin>	Specify VIN (Default: WAUZZZ8V9FA149850)
```

Most of these switches are just for early testing and will eventually be moved
to a config file for more flexibility in fuzzing, etc.

Running uds-server for testing
==============================

If you are running uds-server along with ICSim then simply start another terminal window and
run:d

```
$ uds-server vcan0
```

Then you can practice commands to get VIN or use things like [CaringCaribou] (https://github.com/CaringCaribou/caringcaribou) to brute force or identify diagnostic services.

If you ware working with a dealership tool or a scan tool then you will use the real can0 interface
instead.  You will need a small CAN network to bridge the dealership/scantool with your CAN
sniffer attached to uds-server.  You can breadboard this or build a small portable device we lovingly
call the ODB GW.


ODB GW
======

The ODB Gateway (ODB GW) is a tribute to Ol' Dirty Bastard (RIP) and the mispronunciation 
of OBD (On-board diagnostics) ports.  It is a simple device that you can easily build yourself:

* 2 x Female J1962 OBD-II Ports (~$10/ea)
* Project Box (~$5)
* at least 2 120 Ohm Resistors (or 1 240 Ohm) (pennies)
* 12 V Power Supply (~12)
* Some wires and maybe banana plug connectors

The minimum wiring is as follows:

* Connect pin 12 together for power and splice a line to the 12V supply
* Connect pins 4 and 5 together for ground and splice a line to the 12V supply
* Connect pin 6 together for CAN High
* Connect pin 14 together for CAN Low
* Add 240 Ohm resistance across CAN High and Low

You can bridge more pins but how they are wired depends on what type of vehicle scanner you
are testing.  For instance, several vehicles have many different CAN buses on the other
available pins while other manufacturers use the other pins for different protocols such
as K-Line/KWP.  The above wiring is universal but you may miss out on signals from
dealership tools if you don't also listen on the other pins.

Reversing Dealership Tools
==========================

Using your own CAN network or the ODB GW, plug in a dealership tool or scan tool in one end and 
your sniffer on the other.  Make sure 12V power is supplied to your virtual bus, some scantools
only operate when they have power from pin 16.  Set your CAN bus speeds to be the speed
the dealership tool will expect, for HS CAN this is most likely 500k.

```
$ sudo ip link set can0 up type can bitrate 500000
```

Now run uds-server with the verbose option set on your can0 interface and use the
dealership tool like you would on an actual vehicle.  For example below we use a GM TechII
and request the doors to unlock via the TechII interface.  Looking at the uds-server output
we see:

```
Pkt: 244#01 3E 
Responding with a generic OK message
Pkt: 244#04 AA 03 02 07 
Received GM Read Data by ID Request
 + Medium Rate
Pkt: 244#01 3E 
Responding with a generic OK message
Pkt: 244#07 AE 01 03 00 00 00 00 
Unhandled mode/sid: Device Control (GM)
Pkt: 244#01 3E 
Responding with a generic OK message
Pkt: 101#FE 01 3E 55 55 55 55 55 
Pkt: 244#01 3E 
Responding with a generic OK message
Pkt: 244#02 AE 00 
Unhandled mode/sid: Device Control (GM)
Pkt: 244#01 3E 
Responding with a generic OK message
Pkt: 244#01 3E 
Responding with a generic OK message
Pkt: 244#02 AA 00 
Received GM Read Data by ID Request
 + Stop Data Request
```

In this output the generic OK message refers to a TesterPresent packet sent by the dealership
tool.  We simply respond with OK when we see things like this.  Next the Tool requests some
data to be sent at a Medium interval rate.  uds-server will do that with bogus data.  Then we see
a Device Control (GM) request.  We don't handle it because it's an output request and there is
nothing to spoof.  However the packet info is useful:

```
Pkt: 244#07 AE 01 03 00 00 00 00
Unhandled mode/sid: Device Control (GM)
```

This means that sending 244#07AE010300000000 after sending TesterPresent (244#013E) will unlock
the driver side door.  Later there is another Device Control message to stop doing device
controls 244#02AE00.

This makes it very easy to identify IO controls and to see where data is being requested from.
Often dealership tools won't use the standard UDS mode $09 to get things like VIN but instead they
request VIN and other information via memory locations.

Fuzzing Dealership Tools
========================

If you want to test the security of a dealership tool or scantool then uds-server has a fuzzing
option.  Currently this is still in a Proof of Concept (PoC) stage and it needs to be refined but
the way it currently works is you can specify -z to increase the fuzzing level.  The more -z's you
use the more fuzzing it will do.

For instance:

```
$ uds-server -v -z can0
Using CAN interface can0
Fuzz level set to: 1
```
This will do things like randomize the Vehicle Identification Number (VIN) and some Diagnostic 
Trouble Code (DTC) messages.

```
$ uds-server -v -zzzz can0
Using CAN interface can0
Fuzz level set to: 4
```
This will do things like send WAY too many DTCs (think hundreds) or create HUGE VINs that
also include binary data.  A VIN contains an internal checksum that uds-server will automatically
calculate correctly for fuzzing.  If you want to specify a VIN you can do so via the command
line:

```
$ uds-server -v -V "PWN3D OP3N G4R4G3" can0
```

This will report the vehicles VIN as "PWN3D OP3N G4R4G3" which by the way is a "valid" VIN based on the
checksum byte.  Some tools use VIN as the lookup for what type of vehicle it is working with, so
specifying a valid one for your target vehicle can be useful.

uds-server hacking
==================

Right now new ECU modules need to be added by hand.  Which means you will need to understand the C
code and add handlers for how you want to respond to different types of packets.  Debugging currently
is a hard coded constant as well.  This is because uds-server is still in its PoC stage and could
evolve in many different directions.

Feel free to fork the code and add whatever new handlers you want to add.  Ultimately the fuzzing
configuration and ECU configurations will be handled by a separate config file.

Credits
=======
Craig Smith - craig@theialabs.com
OpenGarages - opengarages.org (@OpenGarages)

