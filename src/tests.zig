const libssz = @import("./main.zig");
const serialize = libssz.encodeSSZ;
const deserialize = libssz.decodeSSZ;
const chunkCount = libssz.chunkCount;
const hashTreeRoot = libssz.hashTreeRoot;
const std = @import("std");
const ArrayList = std.ArrayList;
const expect = std.testing.expect;
const sha256 = std.crypto.hash.sha2.Sha256;

test "serializes uint8" {
    const data: u8 = 0x55;
    const serialized_data = [_]u8{0x55};

    const list = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, serialized_data[0..]));
}

test "serializes uint16" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };

    const list = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, serialized_data[0..]));
}

test "serializes uint32" {
    const data: u32 = 0x55667788;
    const serialized_data = [_]u8{ 0x88, 0x77, 0x66, 0x55 };

    const list = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, serialized_data[0..]));
}

test "serializes a int32" {
    const data: i32 = -(0x11223344);
    const serialized_data = [_]u8{ 0xbc, 0xcc, 0xdd, 0xee };

    const list = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, serialized_data[0..]));
}

test "serializes bool" {
    var data = false;
    var serialized_data = [_]u8{0x00};

    const list = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, serialized_data[0..]));

    data = true;
    serialized_data = [_]u8{0x01};

    const list2 = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list2);
    try expect(std.mem.eql(u8, list2, serialized_data[0..]));
}

test "serializes Bitvector[N] == [N]bool" {
    const data7 = [_]bool{ true, false, true, true, false, false, false };
    var serialized_data = [_]u8{0b00001101};
    var exp = serialized_data[0..serialized_data.len];

    const list7 = try serialize(std.testing.allocator, data7);
    defer std.testing.allocator.free(list7);
    try expect(std.mem.eql(u8, list7, exp));

    const data8 = [_]bool{ true, false, true, true, false, false, false, true };
    serialized_data = [_]u8{0b10001101};
    exp = serialized_data[0..serialized_data.len];

    const list8 = try serialize(std.testing.allocator, data8);
    defer std.testing.allocator.free(list8);
    try expect(std.mem.eql(u8, list8, exp));

    const data12 = [_]bool{ true, false, true, true, false, false, false, true, false, true, false, true };

    const list12 = try serialize(std.testing.allocator, data12);
    defer std.testing.allocator.free(list12);
    try expect(list12.len == 2);
    try expect(list12[0] == 141);
    try expect(list12[1] == 10);
}

test "serializes string" {
    const data = "zig zag";

    const list = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, data));
}

test "serializes an array of shorts" {
    const data = [_]u16{ 0xabcd, 0xef01 };
    const serialized = [_]u8{ 0xcd, 0xab, 0x01, 0xef };

    const list = try serialize(std.testing.allocator, data[0..data.len]);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, serialized[0..]));
}

test "serializes an array of structures" {
    const exp = [_]u8{ 8, 0, 0, 0, 23, 0, 0, 0, 6, 0, 0, 0, 20, 0, 99, 114, 111, 105, 115, 115, 97, 110, 116, 6, 0, 0, 0, 244, 1, 72, 101, 114, 114, 101, 110, 116, 111, 114, 116, 101 };

    const list = try serialize(std.testing.allocator, pastries);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, exp[0..]));
}

test "serializes a structure without variable fields" {
    const data = .{
        .uint8 = @as(u8, 1),
        .uint32 = @as(u32, 3),
        .boolean = true,
    };
    const serialized_data = [_]u8{ 1, 3, 0, 0, 0, 1 };

    const list = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, serialized_data[0..]));
}

test "serializes a structure with variable fields" {
    // Taken from ssz.cr
    const data = .{
        .name = "James",
        .age = @as(u8, 32),
        .company = "DEV Inc.",
    };
    const serialized_data = [_]u8{ 9, 0, 0, 0, 32, 14, 0, 0, 0, 74, 97, 109, 101, 115, 68, 69, 86, 32, 73, 110, 99, 46 };

    const list = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, serialized_data[0..]));
}

test "serializes a structure with optional fields" {
    const Employee = struct {
        name: ?[]const u8,
        age: u8,
        company: ?[]const u8,
    };
    const data: Employee = .{
        .name = "James",
        .age = @as(u8, 32),
        .company = null,
    };

    const serialized_data = [_]u8{ 9, 0, 0, 0, 32, 15, 0, 0, 0, 1, 74, 97, 109, 101, 115, 0 };

    const list = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, serialized_data[0..]));

    const deserialized = try deserialize(Employee, list);
    // only available in >=0.11
    // try std.testing.expectEqualDeep(data, deserialized);
    try expect(std.mem.eql(u8, data.name.?, deserialized.name.?));
    try std.testing.expectEqual(data.age, deserialized.age);
    try std.testing.expectEqual(deserialized.company, null);
}

test "serializes an optional object" {
    const null_or_string: ?[]const u8 = null;
    const list = try serialize(std.testing.allocator, null_or_string);
    defer std.testing.allocator.free(list);
    try expect(list.len == 1);
}

test "serializes a union" {
    const Payload = union(enum) {
        int: u64,
        boolean: bool,
    };

    const exp = [_]u8{ 0, 210, 4, 0, 0, 0, 0, 0, 0 };
    const list = try serialize(std.testing.allocator, Payload{ .int = 1234 });
    defer std.testing.allocator.free(list);
    try expect(std.mem.eql(u8, list, exp[0..]));

    const exp2 = [_]u8{ 1, 1 };
    const list2 = try serialize(std.testing.allocator, Payload{ .boolean = true });
    defer std.testing.allocator.free(list2);
    try expect(std.mem.eql(u8, list2, exp2[0..]));
}

test "deserializes an u8" {
    const payload = [_]u8{0x55};
    const i = try deserialize(u8, payload[0..payload.len]);
    try expect(i == 0x55);
}

test "deserializes an u32" {
    const payload = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const i = try deserialize(u32, payload[0..payload.len]);
    try expect(i == 0x88776655);
}

test "deserializes a boolean" {
    const payload_false = [_]u8{0};
    var b = try deserialize(bool, payload_false[0..1]);
    try expect(!b);

    const payload_true = [_]u8{1};
    b = try deserialize(bool, payload_true[0..1]);
    try expect(b);
}

//test "deserializes a Bitvector[N]" {
//    const exp = [_]bool{ true, false, true, true, false, false, false };
//    const serialized_data = [_]u8{0b00001101};
//    const out = try deserialize([]const u8, serialized_data[0..1]);
//    comptime var i = 0;
//    inline while (i < 7) : (i += 1) {
//        try expect(out[i] == exp[i]);
//    }
//}

test "deserializes an Optional" {
    const exp: ?u32 = 10;
    const list = try serialize(std.testing.allocator, exp);
    defer std.testing.allocator.free(list);
    var out = try deserialize(?u32, list);
    try expect(out.? == exp.?);

    const list2 = try serialize(std.testing.allocator, null);
    defer std.testing.allocator.free(list2);
    out = try deserialize(?u32, list2);
    try expect(out == null);
}

test "deserializes a string" {
    const exp = "croissants";

    const list = try serialize(std.testing.allocator, exp);
    defer std.testing.allocator.free(list);

    const got = try deserialize([]const u8, list);
    try expect(std.mem.eql(u8, exp, got));
}

const Pastry = struct {
    name: []const u8,
    weight: u16,
};

const pastries = [_]Pastry{
    Pastry{
        .name = "croissant",
        .weight = 20,
    },
    Pastry{
        .name = "Herrentorte",
        .weight = 500,
    },
};

test "deserializes a structure" {
    const list = try serialize(std.testing.allocator, pastries[0]);
    defer std.testing.allocator.free(list);
    const out = try deserialize(Pastry, list);

    try expect(pastries[0].weight == out.weight);
    try expect(std.mem.eql(u8, pastries[0].name, out.name));
}

//test "deserializes a Vector[N]" {
//    const list = try serialize(std.testing.allocator, pastries);
//    const out = try deserialize([]const Pastry, list);
//    comptime var i = 0;
//    inline while (i < pastries.len) : (i += 1) {
//        try expect(out[i].weight == pastries[i].weight);
//        try expect(std.mem.eql(u8, pastries[i].name, out[i].name));
//    }
//}

//test "deserializes an invalid Vector[N] payload" {
//    const list = try serialize(std.testing.allocator, pastries);
//    if (deserialize(Pastry, list[0 .. list.len / 2])) {
//        @panic("missed error");
//    } else |err| switch (err) {
//        error.IndexOutOfBounds => {},
//    }
//}

test "deserializes an union" {
    const Payload = union {
        int: u32,
        boolean: bool,
    };
    var p = try deserialize(Payload, ([_]u8{ 1, 1 })[0..]);
    try expect(p.boolean == true);

    p = try deserialize(Payload, ([_]u8{ 1, 0 })[0..]);
    try expect(p.boolean == false);

    p = try deserialize(Payload, ([_]u8{ 0, 1, 2, 3, 4 })[0..]);
    try expect(p.int == 0x04030201);
}

test "serialize/deserialize a u256" {
    const data = [_]u8{0xAA} ** 32;

    const list = try serialize(std.testing.allocator, data);
    defer std.testing.allocator.free(list);
    const output = try deserialize([]const u8, list);

    try expect(std.mem.eql(u8, data[0..], output[0..]));
}

test "chunk count of basic types" {
    try expect(chunkCount(bool) == 1);
    try expect(chunkCount(u8) == 1);
    try expect(chunkCount(u16) == 1);
    try expect(chunkCount(u32) == 1);
    try expect(chunkCount(u64) == 1);
}

test "chunk count of Bitvector[N]" {
    try expect(chunkCount([7]bool) == 1);
    try expect(chunkCount([12]bool) == 1);
    try expect(chunkCount([384]bool) == 2);
}

test "chunk count of Vector[B, N]" {
    try expect(chunkCount([17]u32) == 3);
}

test "chunk count of a struct" {
    try expect(chunkCount(Pastry) == 2);
}

test "chunk count of a Vector[C, N]" {
    try expect(chunkCount([2]Pastry) == 2);
}

// used at comptime to generate a bitvector from a byte vector
fn bytesToBits(comptime N: usize, src: [N]u8) [N * 8]bool {
    var bitvector: [N * 8]bool = undefined;
    for (src, 0..) |byte, idx| {
        var i = 0;
        while (i < 8) : (i += 1) {
            bitvector[i + idx * 8] = ((byte >> (7 - i)) & 1) == 1;
        }
    }
    return bitvector;
}

const a_bytes = [_]u8{0xaa} ** 16;
const b_bytes = [_]u8{0xbb} ** 16;
const c_bytes = [_]u8{0xcc} ** 16;
const d_bytes = [_]u8{0xdd} ** 16;
const e_bytes = [_]u8{0xee} ** 16;
const empty_bytes = [_]u8{0} ** 16;

const a_bits = bytesToBits(16, a_bytes);
const b_bits = bytesToBits(16, b_bytes);
const c_bits = bytesToBits(16, c_bytes);
const d_bits = bytesToBits(16, d_bytes);
const e_bits = bytesToBits(16, e_bytes);

test "calculate the root hash of a boolean" {
    var expected = [_]u8{1} ++ [_]u8{0} ** 31;
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(true, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));

    expected = [_]u8{0} ** 32;
    try hashTreeRoot(false, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate root hash of an array of two Bitvector[128]" {
    const deserialized: [2][128]bool = [2][128]bool{ a_bits, b_bits };
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(deserialized, &hashed, std.testing.allocator);

    var expected: [32]u8 = undefined;
    const expected_preimage = a_bytes ++ empty_bytes ++ b_bytes ++ empty_bytes;
    sha256.hash(expected_preimage[0..], &expected, sha256.Options{});

    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an array of integers" {
    var expected = [_]u8{ 0xef, 0xbe, 0xad, 0xde, 0xfe, 0xca, 0xfe, 0xca } ++ [_]u8{0} ** 24;
    var hashed: [32]u8 = undefined;
    try hashTreeRoot([_]u32{ 0xdeadbeef, 0xcafecafe }, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate root hash of an array of three Bitvector[128]" {
    const deserialized: [3][128]bool = [3][128]bool{ a_bits, b_bits, c_bits };
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(deserialized, &hashed, std.testing.allocator);

    var left: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    const preimg1 = a_bytes ++ empty_bytes ++ b_bytes ++ empty_bytes;
    const preimg2 = c_bytes ++ empty_bytes ** 3;
    sha256.hash(preimg1[0..], &left, sha256.Options{});
    sha256.hash(preimg2[0..], &expected, sha256.Options{});
    var digest = sha256.init(sha256.Options{});
    digest.update(left[0..]);
    digest.update(expected[0..]);
    digest.final(&expected);

    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an array of five Bitvector[128]" {
    const deserialized = [5][128]bool{ a_bits, b_bits, c_bits, d_bits, e_bits };
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(deserialized, &hashed, std.testing.allocator);

    var internal_nodes: [64]u8 = undefined;
    var left: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    const preimg1 = a_bytes ++ empty_bytes ++ b_bytes ++ empty_bytes;
    const preimg2 = c_bytes ++ empty_bytes ++ d_bytes ++ empty_bytes;
    const preimg3 = e_bytes ++ empty_bytes ** 3;
    const preimg4 = empty_bytes ** 4;

    sha256.hash(preimg1[0..], &left, sha256.Options{});
    sha256.hash(preimg2[0..], internal_nodes[0..32], sha256.Options{});
    var digest = sha256.init(sha256.Options{});
    digest.update(left[0..]);
    digest.update(internal_nodes[0..32]);
    digest.final(internal_nodes[0..32]);

    sha256.hash(preimg3[0..], &left, sha256.Options{});
    sha256.hash(preimg4[0..], internal_nodes[32..], sha256.Options{});
    digest = sha256.init(sha256.Options{});
    digest.update(left[0..]);
    digest.update(internal_nodes[32..]);
    digest.final(internal_nodes[32..]);

    sha256.hash(internal_nodes[0..], &expected, sha256.Options{});

    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

const Fork = struct {
    previous_version: [4]u8,
    current_version: [4]u8,
    epoch: u64,
};

test "calculate the root hash of a structure" {
    var hashed: [32]u8 = undefined;
    const fork = Fork{
        .previous_version = [_]u8{ 0x9c, 0xe2, 0x5d, 0x26 },
        .current_version = [_]u8{ 0x36, 0x90, 0x55, 0x93 },
        .epoch = 3,
    };
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected[0..], "58316a908701d3660123f0b8cb7839abdd961f71d92993d34e4f480fbec687d9");
    try hashTreeRoot(fork, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an Optional" {
    var hashed: [32]u8 = undefined;
    var payload: [64]u8 = undefined;
    const v: ?u32 = null;
    const u: ?u32 = 0xdeadbeef;
    var expected: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(payload[0..], "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    sha256.hash(payload[0..], expected[0..], sha256.Options{});
    try hashTreeRoot(v, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));

    _ = try std.fmt.hexToBytes(payload[0..], "efbeadde000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000");
    sha256.hash(payload[0..], expected[0..], sha256.Options{});
    try hashTreeRoot(u, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an union" {
    const Payload = union(enum) {
        int: u64,
        boolean: bool,
    };
    var out: [32]u8 = undefined;
    var payload: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(payload[0..], "d2040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    var exp1: [32]u8 = undefined;
    sha256.hash(payload[0..], exp1[0..], sha256.Options{});
    try hashTreeRoot(Payload{ .int = 1234 }, &out, std.testing.allocator);
    try expect(std.mem.eql(u8, out[0..], exp1[0..]));

    var exp2: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(payload[0..], "01000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000");
    sha256.hash(payload[0..], exp2[0..], sha256.Options{});
    try hashTreeRoot(Payload{ .boolean = true }, &out, std.testing.allocator);
    try expect(std.mem.eql(u8, out[0..], exp2[0..]));
}
