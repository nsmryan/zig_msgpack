const std = @import("std");
const assert = std.debug.assert;
const expect = std.testing.expect;
const builtin = std.builtin;
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

pub const Error = MsgPackError || std.mem.Allocator.Error;
pub const MsgPackError = error{ InvalidMsgId, BufferToSmall };

pub const FamilyId = enum {
    Integer,
    Nil,
    Boolean,
    Float,
    String,
    Raw,
    Array,
    Map,
    Extension,
};

pub const IdData = struct {
    mask: u8,
    value: u8,

    pub fn init(mask: u8, value: u8) IdData {
        return IdData{ .mask = mask, .value = value };
    }
};

pub const MsgId = enum {
    PosFixedInt,
    FixMap,
    FixArray,
    FixStr,
    Nil,
    False,
    True,
    Bin8,
    Bin16,
    Bin32,
    Ext8,
    Ext16,
    Ext32,
    Float32,
    Float64,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    FixExt1,
    FixExt2,
    FixExt4,
    FixExt8,
    FixExt16,
    Str8,
    Str16,
    Str32,
    Array16,
    Array32,
    Map16,
    Map32,
    NegFixedInt,

    pub fn byte_to_id(byte: u8) !MsgId {
        inline for (@typeInfo(MsgId).Enum.fields) |field| {
            const msg_id = @intToEnum(MsgId, field.value);
            const msg_def = MsgId.def(msg_id);
            if (byte & msg_def.mask == msg_def.value) {
                return msg_id;
            }
        }

        return Error.InvalidMsgId;
    }

    pub fn id_to_byte(id: MsgId) u8 {
        return id.def().value;
    }

    pub fn def(id: MsgId) IdData {
        switch (id) {
            MsgId.PosFixedInt => return IdData.init(0b10000000, 0b00000000),
            MsgId.FixMap => return IdData.init(0b11110000, 0b10000000),
            MsgId.FixArray => return IdData.init(0b11110000, 0b10010000),
            MsgId.FixStr => return IdData.init(0b11100000, 0b10100000),
            MsgId.Nil => return IdData.init(0b11111111, 0b11000000),
            MsgId.False => return IdData.init(0b11111111, 0b11000010),
            MsgId.True => return IdData.init(0b11111111, 0b11000011),
            MsgId.Bin8 => return IdData.init(0b11111111, 0b11000100),
            MsgId.Bin16 => return IdData.init(0b11111111, 0b11000101),
            MsgId.Bin32 => return IdData.init(0b11111111, 0b11000110),
            MsgId.Ext8 => return IdData.init(0b11111111, 0b11000111),
            MsgId.Ext16 => return IdData.init(0b11111111, 0b11001000),
            MsgId.Ext32 => return IdData.init(0b11111111, 0b11001001),
            MsgId.Float32 => return IdData.init(0b11111111, 0b11001010),
            MsgId.Float64 => return IdData.init(0b11111111, 0b11001011),
            MsgId.U8 => return IdData.init(0b11111111, 0b11001100),
            MsgId.U16 => return IdData.init(0b11111111, 0b11001101),
            MsgId.U32 => return IdData.init(0b11111111, 0b11001110),
            MsgId.U64 => return IdData.init(0b11111111, 0b11001111),
            MsgId.I8 => return IdData.init(0b11111111, 0b11010000),
            MsgId.I16 => return IdData.init(0b11111111, 0b11010001),
            MsgId.I32 => return IdData.init(0b11111111, 0b11010010),
            MsgId.I64 => return IdData.init(0b11111111, 0b11010011),
            MsgId.FixExt1 => return IdData.init(0b11111111, 0b11010100),
            MsgId.FixExt2 => return IdData.init(0b11111111, 0b11010101),
            MsgId.FixExt4 => return IdData.init(0b11111111, 0b11010110),
            MsgId.FixExt8 => return IdData.init(0b11111111, 0b11010111),
            MsgId.FixExt16 => return IdData.init(0b11111111, 0b11011000),
            MsgId.Str8 => return IdData.init(0b11111111, 0b11011001),
            MsgId.Str16 => return IdData.init(0b11111111, 0b11011001),
            MsgId.Str32 => return IdData.init(0b11111111, 0b11011011),
            MsgId.Array16 => return IdData.init(0b11111111, 0b11011100),
            MsgId.Array32 => return IdData.init(0b11111111, 0b11011101),
            MsgId.Map16 => return IdData.init(0b11111111, 0b11011110),
            MsgId.Map32 => return IdData.init(0b11111111, 0b11011111),
            MsgId.NegFixedInt => return IdData.init(0b11100000, 0b11100000),
        }
    }

    /// This function returns the number of bytes required
    /// to parse a token. We have already determined that
    /// we have enough bytes to determine the length of the
    /// token, including any length field after the ID.
    pub fn token_length_bytes(id: MsgId, buffer: []const u8) u64 {
        return 1 + switch (id) {
            MsgId.FixStr => buffer[0] & ~id.def().mask,
            MsgId.Bin8 => @sizeOf(u8) + read_be_int(u8, buffer[1..2]),
            MsgId.Bin16 => @sizeOf(u16) + read_be_int(u16, buffer[1..3]),
            MsgId.Bin32 => @sizeOf(u32) + read_be_int(u32, buffer[1..5]),
            MsgId.Ext8 => @sizeOf(u8) + read_be_int(u8, buffer[1..2]),
            MsgId.Ext16 => @sizeOf(u16) + read_be_int(u16, buffer[1..3]),
            MsgId.Ext32 => @sizeOf(u32) + read_be_int(u32, buffer[1..5]),
            MsgId.Float32 => @sizeOf(f32),
            MsgId.Float64 => @sizeOf(f64),
            MsgId.U8 => @sizeOf(u8),
            MsgId.U16 => @sizeOf(u16),
            MsgId.U32 => @sizeOf(u32),
            MsgId.U64 => @sizeOf(u64),
            MsgId.I8 => @sizeOf(i8),
            MsgId.I16 => @sizeOf(i16),
            MsgId.I32 => @sizeOf(i32),
            MsgId.I64 => @sizeOf(i64),
            MsgId.FixExt1 => @sizeOf(u8) + @sizeOf(u8),
            MsgId.FixExt2 => @sizeOf(u8) + @sizeOf(u16),
            MsgId.FixExt4 => @sizeOf(u8) + @sizeOf(u32),
            MsgId.FixExt8 => @sizeOf(u8) + @sizeOf(u64),
            MsgId.FixExt16 => @sizeOf(u8) + @sizeOf(u128),
            MsgId.Str8 => @sizeOf(u8) + read_be_int(u8, buffer[1..2]),
            MsgId.Str16 => @sizeOf(u16) + read_be_int(u32, buffer[1..3]),
            MsgId.Str32 => @sizeOf(u32) + read_be_int(u16, buffer[1..5]),
            MsgId.Array16 => @sizeOf(u16),
            MsgId.Array32 => @sizeOf(u33),
            MsgId.Map16 => @sizeOf(u16),
            MsgId.Map32 => @sizeOf(u32),
            else => 0,
        };
    }

    /// Return the number of bytes needed after the msg id byte before we know the
    /// full size of the message field. For example, a Pos Fixed Int does not need
    /// any more bytes as it is self contained, but a Bin8 need another u8
    /// to determine the message size.
    pub fn bytes_needed_to_get_size(id: MsgId) u64 {
        switch (id) {
            MsgId.PosFixedInt => return @sizeOf(void),
            MsgId.FixMap => return @sizeOf(void),
            MsgId.FixArray => return @sizeOf(void),
            MsgId.FixStr => return @sizeOf(void),
            MsgId.Nil => return @sizeOf(void),
            MsgId.False => return @sizeOf(void),
            MsgId.True => return @sizeOf(void),
            MsgId.Bin8 => return @sizeOf(u8),
            MsgId.Bin16 => return @sizeOf(u16),
            MsgId.Bin32 => return @sizeOf(u32),
            MsgId.Ext8 => return @sizeOf(void),
            MsgId.Ext16 => return @sizeOf(void),
            MsgId.Ext32 => return @sizeOf(void),
            MsgId.Float32 => return @sizeOf(void),
            MsgId.Float64 => return @sizeOf(void),
            MsgId.U8 => return @sizeOf(void),
            MsgId.U16 => return @sizeOf(void),
            MsgId.U32 => return @sizeOf(void),
            MsgId.U64 => return @sizeOf(void),
            MsgId.I8 => return @sizeOf(void),
            MsgId.I16 => return @sizeOf(void),
            MsgId.I32 => return @sizeOf(void),
            MsgId.I64 => return @sizeOf(void),
            MsgId.FixExt1 => return @sizeOf(void),
            MsgId.FixExt2 => return @sizeOf(void),
            MsgId.FixExt4 => return @sizeOf(void),
            MsgId.FixExt8 => return @sizeOf(void),
            MsgId.FixExt16 => return @sizeOf(void),
            MsgId.Str8 => return @sizeOf(void),
            MsgId.Str16 => return @sizeOf(void),
            MsgId.Str32 => return @sizeOf(void),
            MsgId.Array16 => return @sizeOf(u16),
            MsgId.Array32 => return @sizeOf(u32),
            MsgId.Map16 => return @sizeOf(u16),
            MsgId.Map32 => return @sizeOf(u32),
            MsgId.NegFixedInt => return @sizeOf(void),
        }
    }
};

pub const Extension = struct {
    typ: u8,
    data: []const u8,

    pub fn init(typ: u64, data: []u8) Extension {
        return Extension{ .typ = typ, .data = data };
    }
};

pub fn MsgData(comptime T: type) type {
    return packed struct {
        msg_id: u8,
        payload: T,
    };
}

pub fn ExtData(comptime T: type) type {
    return packed struct {
        typ: u8,
        data: T,
    };
}

pub const NumEntries = u64;

pub const Token = union(FamilyId) {
    Integer: i64,
    Nil: void,
    Boolean: bool,
    Float: f64,
    String: []const u8,
    Raw: []const u8,
    Array: NumEntries,
    Map: NumEntries,
    Extension: Extension,

    // NOTE This function assumes that the buffer
    // has enough bytes to parse a message. This
    // precondition is checked internally to this library
    // before calling this function.
    fn parse(buffer: []const u8) Error!Token {
        const id_byte = buffer[0];
        const id = try MsgId.byte_to_id(id_byte);
        const def = MsgId.def(id);

        switch (id) {
            MsgId.PosFixedInt => {
                return Token{ .Integer = @as(i64, id_byte & ~def.mask) };
            },
            MsgId.FixMap => {
                return Token{ .Map = id_byte & ~def.mask };
            },
            MsgId.FixArray => {
                return Token{ .Array = @as(u64, id_byte & ~def.mask) };
            },
            MsgId.FixStr => {
                const byte_len = id_byte & (~def.mask);
                return Token{ .String = buffer[1 .. 1 + byte_len] };
            },
            MsgId.Nil => {
                const nil: Token = Token.Nil;
                return nil;
            },
            MsgId.False => {
                return Token{ .Boolean = false };
            },
            MsgId.True => {
                return Token{ .Boolean = true };
            },
            MsgId.Bin8 => {
                const byte_len = read_be_int(u8, buffer[1 .. 1 + @sizeOf(u8)]);
                return Token{ .Raw = buffer[1..byte_len] };
            },
            MsgId.Bin16 => {
                const byte_len = read_be_int(u16, buffer[1 .. 1 + @sizeOf(u16)]);
                return Token{ .Raw = buffer[1..byte_len] };
            },
            MsgId.Bin32 => {
                const byte_len = read_be_int(u32, buffer[1 .. 1 + @sizeOf(u32)]);
                return Token{ .Raw = buffer[1..byte_len] };
            },
            MsgId.Ext8 => {
                const ext_data = @ptrCast(*const MsgData(ExtData([1]u8)), &buffer);
                const data: []const u8 = ext_data.payload.data[0..1];
                return Token{ .Extension = Extension{ .typ = ext_data.payload.typ, .data = data } };
            },
            MsgId.Ext16 => {
                const ext_data = @ptrCast(*const MsgData(ExtData([2]u8)), &buffer);
                const data: []const u8 = ext_data.payload.data[0..2];
                return Token{ .Extension = Extension{ .typ = ext_data.payload.typ, .data = data } };
            },
            MsgId.Ext32 => {
                const ext_data = @ptrCast(*const MsgData(ExtData([4]u8)), &buffer);
                const data: []const u8 = ext_data.payload.data[0..4];
                return Token{ .Extension = Extension{ .typ = ext_data.payload.typ, .data = data } };
            },
            MsgId.Float32 => {
                var raw_val: u32 = read_be_int(u32, buffer[1 .. 1 + @sizeOf(f32)]);
                const val = @ptrCast(*const f32, &raw_val).*;
                return Token{ .Float = @as(f64, val) };
            },
            MsgId.Float64 => {
                var raw_val: u64 = read_be_int(u64, buffer[1 .. 1 + @sizeOf(f64)]);
                const val = @ptrCast(*const f64, &raw_val).*;
                return Token{ .Float = @as(f64, val) };
            },
            MsgId.U8 => {
                const msg = @ptrCast(*const MsgData(u8), &buffer);
                return Token{ .Integer = @as(i64, @byteSwap(u8, msg.payload)) };
            },
            MsgId.U16 => {
                const msg = @ptrCast(*const MsgData(u16), &buffer);
                return Token{ .Integer = @as(i64, @byteSwap(u16, msg.payload)) };
            },
            MsgId.U32 => {
                const msg = @ptrCast(*const MsgData(u32), &buffer);
                return Token{ .Integer = @as(i64, @byteSwap(u32, msg.payload)) };
            },
            MsgId.U64 => {
                // TODO is i64 right here?
                const msg = @ptrCast(*const MsgData(u64), &buffer);
                return Token{ .Integer = @intCast(i64, @byteSwap(u64, msg.payload)) };
            },
            MsgId.I8 => {
                const msg = @ptrCast(*const MsgData(i8), &buffer);
                return Token{ .Integer = @as(i64, @byteSwap(i8, msg.payload)) };
            },
            MsgId.I16 => {
                const msg = @ptrCast(*const MsgData(i16), &buffer);
                return Token{ .Integer = @as(i64, @byteSwap(i16, msg.payload)) };
            },
            MsgId.I32 => {
                const msg = @ptrCast(*const MsgData(i32), &buffer);
                return Token{ .Integer = @as(i64, @byteSwap(i32, msg.payload)) };
            },
            MsgId.I64 => {
                const msg = @ptrCast(*const MsgData(i64), &buffer);
                return Token{ .Integer = @as(i64, @byteSwap(i64, msg.payload)) };
            },
            MsgId.FixExt1 => {
                const msg = @ptrCast(*const MsgData([1]u8), &buffer);
                return Token{ .Extension = Extension{ .typ = msg.msg_id, .data = &msg.payload } };
            },
            MsgId.FixExt2 => {
                const msg = @ptrCast(*const MsgData([2]u8), &buffer);
                return Token{ .Extension = Extension{ .typ = msg.msg_id, .data = &msg.payload } };
            },
            MsgId.FixExt4 => {
                const msg = @ptrCast(*const MsgData([4]u8), &buffer);
                return Token{ .Extension = Extension{ .typ = msg.msg_id, .data = &msg.payload } };
            },
            MsgId.FixExt8 => {
                const msg = @ptrCast(*const MsgData([8]u8), &buffer);
                return Token{ .Extension = Extension{ .typ = msg.msg_id, .data = &msg.payload } };
            },
            MsgId.FixExt16 => {
                const msg = @ptrCast(*const MsgData([16]u8), &buffer);
                return Token{ .Extension = Extension{ .typ = msg.msg_id, .data = &msg.payload } };
            },
            MsgId.Str8 => {
                const num_bytes = read_be_int(u8, buffer[1 .. 1 + @sizeOf(u8)]);
                const data_offset = @sizeOf(u8) + @sizeOf(u8);
                return Token{ .String = buffer[data_offset .. data_offset + num_bytes] };
            },
            MsgId.Str16 => {
                const num_bytes = read_be_int(u16, buffer[1 .. 1 + @sizeOf(u16)]);
                const data_offset = @sizeOf(u8) + @sizeOf(u16);
                return Token{ .String = buffer[data_offset .. data_offset + num_bytes] };
            },
            MsgId.Str32 => {
                const num_bytes = read_be_int(u32, buffer[1 .. 1 + @sizeOf(u32)]);
                const data_offset = @sizeOf(u8) + @sizeOf(u32);
                return Token{ .String = buffer[data_offset .. data_offset + num_bytes] };
            },
            MsgId.Array16 => {
                const msg = @ptrCast(*const MsgData(u16), buffer);
                return Token{ .Array = @byteSwap(u16, msg.payload) };
            },
            MsgId.Array32 => {
                const msg = @ptrCast(*const MsgData(u32), &buffer);
                return Token{ .Array = @byteSwap(u32, msg.payload) };
            },
            MsgId.Map16 => {
                const msg = @ptrCast(*const MsgData(u16), &buffer);
                return Token{ .Map = @byteSwap(u16, msg.payload) };
            },
            MsgId.Map32 => {
                const msg = @ptrCast(*const MsgData(u32), &buffer);
                return Token{ .Map = @byteSwap(u32, msg.payload) };
            },
            MsgId.NegFixedInt => {
                return Token{ .Integer = @as(i64, id_byte & ~def.mask) };
            },
        }
    }
};

pub const ParsedToken = struct {
    Token: Token,
    token_length_bytes: u64,
};

pub const Result = union(enum) {
    ParsedToken: ParsedToken,
    MoreBytes: u64,
};

/// Given a buffer that may contain a MsgPack message, attempt to
/// parse the message. This either returns a Token, indicating the
/// next parsed object in the stream, or a request for more bytes
/// with the number of bytes needed to make progress.
///
/// This does not mean that if this number of bytes is given,
/// that parse will require a Token, only that this is the number
/// of bytes needed before we can make progress parsing the message.
pub fn parse_token(buffer: []const u8) Error!Result {
    // if there are not enough bytes for a message id, ask for a byte
    if (buffer.len < 1) {
        return Result{ .MoreBytes = 1 };
    }

    const id_byte = buffer[0];
    const id = try MsgId.byte_to_id(id_byte);
    const bytes_needed = id.bytes_needed_to_get_size();

    // if we need more bytes to determine the message's length,
    // request those bytes.
    if (bytes_needed > buffer.len) {
        return Result{ .MoreBytes = bytes_needed - buffer.len };
    }

    const token_size = id.token_length_bytes(buffer);

    // if we don't have enough bytes for the full token
    // ask for those bytes.
    if (token_size > buffer.len) {
        return Result{ .MoreBytes = token_size - buffer.len };
    }

    // we have enough bytes to parse out the token
    const token = try Token.parse(buffer);
    const parsed_token = ParsedToken{ .Token = token, .token_length_bytes = token_size };
    return Result{ .ParsedToken = parsed_token };
}

test "test basic tokens" {
    // PosFixedInt
    {
        const value = 0b01010101;
        const bits = MsgId.def(MsgId.PosFixedInt).value | value;
        const bytes = [_]u8{bits};
        const msg = try parse_token(bytes[0..]);
        const expected = Result{ .ParsedToken = ParsedToken{ .Token = Token{ .Integer = value }, .token_length_bytes = 1 } };
        assert(std.meta.eql(msg, expected));
    }

    //// NegFixedInt
    //{
    //    const value = 0b00000101;
    //    const bits = MsgId.def(MsgId.NegFixedInt).value | value;
    //    const bytes = [_]u8{bits};
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    //std.debug.print("msg = {}", .{msg});
    //    assert(std.meta.eql(msg, MsgPack{ .Integer = value }));
    //}
    //// True
    //{
    //    const bits = MsgId.def(MsgId.True).value;
    //    const bytes = [_]u8{bits};
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    expect(std.meta.eql(msg, MsgPack{ .Boolean = true }));
    //}
    //// False
    //{
    //    const bits = MsgId.def(MsgId.False).value;
    //    const bytes = [_]u8{bits};
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    expect(std.meta.eql(msg, MsgPack{ .Boolean = false }));
    //}
    //// I8
    //{
    //    const value: u8 = 0x34;
    //    const bits = MsgId.def(MsgId.I8).value;
    //    const bytes = [_]u8{ bits, value };
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    expect(std.meta.eql(msg, MsgPack{ .Integer = value }));
    //}
    //// I16
    //{
    //    const value: u16 = 0x1234;
    //    const bits = MsgId.def(MsgId.I16).value;
    //    const bytes = [_]u8{ bits, @intCast(u8, (value >> 8) & 0xFF), @intCast(u8, value & 0xFF) };
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    expect(std.meta.eql(msg, MsgPack{ .Integer = value }));
    //}
    //// I32
    //{
    //    const value: u32 = 0x1234;
    //    const bits = MsgId.def(MsgId.I32).value;
    //    var bytes = [_]u8{ bits, 0, 0, 0, 0 };
    //    bytes[1] = @as(u8, (value >> 24) & 0xFF);
    //    bytes[2] = @as(u8, (value >> 16) & 0xFF);
    //    bytes[3] = @as(u8, (value >> 8) & 0xFF);
    //    bytes[4] = @as(u8, (value >> 0) & 0xFF);
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    expect(std.meta.eql(msg, MsgPack{ .Integer = value }));
    //}
    //// I64
    //{
    //    const value: u64 = 0x12345678;
    //    const bits = MsgId.def(MsgId.I64).value;
    //    var bytes = [_]u8{ bits, 0, 0, 0, 0, 0, 0, 0, 0 };
    //    bytes[1] = @as(u8, (value >> 56) & 0xFF);
    //    bytes[2] = @as(u8, (value >> 48) & 0xFF);
    //    bytes[3] = @as(u8, (value >> 40) & 0xFF);
    //    bytes[4] = @as(u8, (value >> 32) & 0xFF);
    //    bytes[5] = @as(u8, (value >> 24) & 0xFF);
    //    bytes[6] = @as(u8, (value >> 16) & 0xFF);
    //    bytes[7] = @as(u8, (value >> 8) & 0xFF);
    //    bytes[8] = @as(u8, (value >> 0) & 0xFF);
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    //std.debug.print("msg = {}", .{msg});
    //    expect(std.meta.eql(msg, MsgPack{ .Integer = @as(i64, value) }));
    //}
    //// U8
    //{
    //    const value: u8 = 0x34;
    //    const bits = MsgId.def(MsgId.U8).value;
    //    const bytes = [_]u8{ bits, value };
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    expect(std.meta.eql(msg, MsgPack{ .Integer = value }));
    //}
    //// U16
    //{
    //    const value: u16 = 0x1234;
    //    const bits = MsgId.def(MsgId.U16).value;
    //    const bytes = [_]u8{ bits, @intCast(u8, (value >> 8) & 0xFF), @intCast(u8, value & 0xFF) };
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    expect(std.meta.eql(msg, MsgPack{ .Integer = value }));
    //}
    //// U32
    //{
    //    const value: u32 = 0x1234;
    //    const bits = MsgId.def(MsgId.U32).value;
    //    var bytes = [_]u8{ bits, 0, 0, 0, 0 };
    //    bytes[1] = @as(u8, (value >> 24) & 0xFF);
    //    bytes[2] = @as(u8, (value >> 16) & 0xFF);
    //    bytes[3] = @as(u8, (value >> 8) & 0xFF);
    //    bytes[4] = @as(u8, (value >> 0) & 0xFF);
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    expect(std.meta.eql(msg, MsgPack{ .Integer = value }));
    //}
    //// U64
    //{
    //    const value: u64 = 0x12345678;
    //    const bits = MsgId.def(MsgId.U64).value;
    //    var bytes = [_]u8{ bits, 0, 0, 0, 0, 0, 0, 0, 0 };
    //    bytes[1] = @as(u8, (value >> 56) & 0xFF);
    //    bytes[2] = @as(u8, (value >> 48) & 0xFF);
    //    bytes[3] = @as(u8, (value >> 40) & 0xFF);
    //    bytes[4] = @as(u8, (value >> 32) & 0xFF);
    //    bytes[5] = @as(u8, (value >> 24) & 0xFF);
    //    bytes[6] = @as(u8, (value >> 16) & 0xFF);
    //    bytes[7] = @as(u8, (value >> 8) & 0xFF);
    //    bytes[8] = @as(u8, (value >> 0) & 0xFF);
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    //std.debug.print("msg = {}", .{msg});
    //    expect(std.meta.eql(msg, MsgPack{ .Integer = @as(i64, value) }));
    //}
    //// Nil
    //{
    //    const nil_bits = MsgId.def(MsgId.Nil).value;
    //    const bytes = [_]u8{nil_bits};
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    assert(std.meta.eql(msg, MsgPack.Nil));
    //}
    //// F32
    //{
    //    const value: f32 = 123.0;
    //    const bits = MsgId.def(MsgId.Float32).value;
    //    var bytes = [_]u8{ bits, 0, 0, 0, 0 };

    //    const raw_val = @ptrCast(*const u32, &value).*;
    //    bytes[1] = @as(u8, (raw_val >> 24) & 0xFF);
    //    bytes[2] = @as(u8, (raw_val >> 16) & 0xFF);
    //    bytes[3] = @as(u8, (raw_val >> 8) & 0xFF);
    //    bytes[4] = @as(u8, (raw_val >> 0) & 0xFF);
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    //std.debug.print("msg = {}", .{msg});
    //    expect(std.meta.eql(msg, MsgPack{ .Float = @as(f64, value) }));
    //}
    //// F64
    //{
    //    const value: f64 = 123.0;
    //    const bits = MsgId.def(MsgId.Float64).value;
    //    var bytes = [_]u8{ bits, 0, 0, 0, 0, 0, 0, 0, 0 };

    //    const raw_val = @ptrCast(*const u64, &value).*;
    //    bytes[1] = @as(u8, (raw_val >> 56) & 0xFF);
    //    bytes[2] = @as(u8, (raw_val >> 48) & 0xFF);
    //    bytes[3] = @as(u8, (raw_val >> 40) & 0xFF);
    //    bytes[4] = @as(u8, (raw_val >> 32) & 0xFF);
    //    bytes[5] = @as(u8, (raw_val >> 24) & 0xFF);
    //    bytes[6] = @as(u8, (raw_val >> 16) & 0xFF);
    //    bytes[7] = @as(u8, (raw_val >> 8) & 0xFF);
    //    bytes[8] = @as(u8, (raw_val >> 0) & 0xFF);
    //    const msg = try msg_pack_decode(std.testing.allocator, bytes[0..]);
    //    //std.debug.print("msg = {}", .{msg});
    //    expect(std.meta.eql(msg, MsgPack{ .Float = value }));
    //}
}

pub fn read_be_int(comptime t: type, buffer: [*]const u8) t {
    var val: t = undefined;
    @memcpy(@ptrCast([*]u8, &val), buffer, @sizeOf(t));

    if (std.builtin.endian == std.builtin.Endian.Little) {
        val = @byteSwap(t, val);
    }

    return val;
}

pub const KeyValue = struct {
    key: MsgPack,
    value: MsgPack,
};

pub const MsgPack = union(FamilyId) {
    Integer: i64,
    Nil: void,
    Boolean: bool,
    Float: f64,
    String: []u8,
    Raw: []u8,
    Array: []MsgPack,
    Map: []KeyValue,
    Extension: Extension,

    pub fn deinit(self: MsgPack, allocator: *Allocator) void {
        switch (self) {
            FamilyId.Integer => return,
            FamilyId.Nil => return,
            FamilyId.Boolean => return,
            FamilyId.Float => return,
            FamilyId.String => |string| {
                allocator.free(string);
            },
            FamilyId.Raw => |ptr| {
                allocator.free(ptr);
            },
            FamilyId.Array => |array| {
                for (array) |msg| {
                    msg.deinit(allocator);
                }
                allocator.free(array);
            },
            FamilyId.Map => |keyvalues| {
                for (keyvalues) |pair| {
                    pair.key.deinit(allocator);
                    pair.value.deinit(allocator);
                }
                allocator.free(keyvalues);
            },
            FamilyId.Extension => |extension| {
                allocator.free(extension.data);
            },
        }
    }
};
