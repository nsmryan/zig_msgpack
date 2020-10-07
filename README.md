# MsgPack in Zig
This repository contains an attempt to implement the [MsgPack](https://github.com/msgpack/msgpack) serialization 
format in Zig. This format is pretty interesting- its like a binary JSON, but more compact, supporting binary
buffers, and supporting maps between arbitrary objects.

I attempted to implement this protocol in Zig to see how a binary protocol would work with Zig's type system.
Overall I think Zig offers some interesting advantages compared to, say, C, but I did run into problems as well.
I was able to encode some aspects of the protocol in the type system, which is nice, but ran into some issues
with type resolution in complex transformations (not too big of a deal), and a codegen crash.


Ideally I think a Zig MsgPack implementation could have a zero-copy interface for fast parsing, and should be
able to automatically encode and decode types (at least basic types). This would make MsgPack a more compact
alternative to the JSON interface in the Zig standard library.


## Design
The API that is currently, mostly, implemented is that the user provides a buffer that is expected to contain a MsgPack
message to the parse\_token function, and this function returns whether more bytes are needed (an how many), or a Token
which indicates part of a message, and the number of bytes that the token takes up.


The idea is that you have bytes available from some source, such as a TCP/IP socket or file, and you want to parse out
MsgPack structures. The parse\_token function provides the next MsgPack structure in the buffer, and how many bytes to
move forward to find the next structure. This does not require any allocation- the Token structure is small and contains
slices into the buffer provided by the user.


For some structures (maps and arrays), the Token only indicates the number of elements that follow, but does not attempt
to parse those tokens. The user is responsible for keeping track of how many elements are needed, and whether they
are in a nested map or array. This keeps the tokens small.


The token interface was going to be the basic interface on top of which other interfaces could be built. You could
keep calling this function, skipping over the bytes it reports having parsed, and build up the structure you are interested
in.


I was intending to also provide functions to build up a kind of "simple" MsgPack structure that unpacked a buffer
into a single fully parsed structure. This would not necessarily be the most efficient- it would allocate buffers for string, arrays,
maps, binary buffers, etc, but it would serve as a simple test case and an interface to test against.


The next intended feature was to implement a function that would accept a pointer to a structure of some type,
and a buffer, and would attempt to fill out the fields of the structure with the contents of the buffer decoded
as a MsgPack structure. If we could then implement the opposite, you could use this library as a kind of serialize/
deserialize for any type to send it to another program. Zig's compile time programming would make this fairly
straightforward, which is intriguing to me.


## Issues
I was not able to finish the token interface due to some kind of segfault in code generation. I could not figure out more,
such as where in the code the problem occurred, but I have not been able to test or run the code.


Ideally I will come back to this project some time in the future and figure out where the codegen issue is- perhaps 
I'm doing something too tricky and causing a crash, and perhaps future versions of Zig will catch the error (if
it is actually an unrealized type error) or just generate the code and run.
